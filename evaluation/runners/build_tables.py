from __future__ import annotations

import argparse
import math
from collections import defaultdict
from pathlib import Path
from statistics import mean
from typing import Any

from evaluation.metrics import summarize
from evaluation.recording import read_jsonl, write_csv, write_jsonl
from evaluation.schema import TaskRunRecord


def _rate(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _load_tasks(root: Path) -> list[TaskRunRecord]:
    return [
        TaskRunRecord.model_validate(item)
        for item in read_jsonl(root / "raw" / "statefulbench_tasks.jsonl")
    ]


def build_tables(output_root: str | Path = "evaluation/results") -> None:
    root = Path(output_root)
    tasks = _load_tasks(root)
    summaries = summarize(tasks)
    write_jsonl(root / "normalized" / "all_summary.jsonl", summaries)
    principal = [row for row in summaries if row["defense"] in {"No Defense", "A4 Full AgentGate"}]

    security_fields = [
        "benchmark",
        "defense",
        "attack_total",
        "attack_success_count",
        "attack_blocked_count",
        "asr",
        "asr_ci_low",
        "asr_ci_high",
        "defense_success_rate",
        "harmful_side_effect_count",
        "attack_prevented_before_side_effect_count",
        "late_detection_count",
    ]
    security_rows = []
    for row in principal:
        matching = [
            item
            for item in tasks
            if item.benchmark == row["benchmark"]
            and item.defense == row["defense"]
            and item.is_attack
        ]
        security_rows.append(
            {
                **row,
                "attack_prevented_before_side_effect_count": sum(
                    item.attack_prevented_before_side_effect for item in matching
                ),
            }
        )
    write_csv(root / "tables" / "rq1_security_effectiveness.csv", security_rows, security_fields)

    utility_fields = [
        "benchmark",
        "defense",
        "benign_task_total",
        "benign_task_success_count",
        "bcr",
        "bcr_ci_low",
        "bcr_ci_high",
        "benign_blocked_count",
        "benign_degraded_count",
        "mean_tool_calls",
        "mean_turns",
        "mean_trajectory_length",
    ]
    utility_rows = []
    for row in principal:
        matching = [
            item
            for item in tasks
            if item.benchmark == row["benchmark"]
            and item.defense == row["defense"]
            and not item.is_attack
        ]
        utility_rows.append(
            {
                **row,
                "benign_degraded_count": sum(item.benign_degraded for item in matching),
                "mean_tool_calls": mean(item.tool_calls for item in matching),
                "mean_turns": mean(item.turns for item in matching),
                "mean_trajectory_length": mean(item.trajectory_length for item in matching),
            }
        )
    write_csv(root / "tables" / "rq1_benign_utility.csv", utility_rows, utility_fields)

    _build_rq1_risk_scenarios(root, tasks)
    _build_gateway_confusion_matrix(root, tasks)
    _build_rq2(root, tasks, summaries)
    _ensure_model_table_schemas(root)
    _write_failure_cases(root, tasks)


def _note_value(item: TaskRunRecord, prefix: str) -> str:
    return next(
        (note.removeprefix(prefix) for note in item.notes if note.startswith(prefix)),
        "",
    )


def _build_rq1_risk_scenarios(root: Path, tasks: list[TaskRunRecord]) -> None:
    full_attacks = [
        item for item in tasks if item.defense == "A4 Full AgentGate" and item.is_attack
    ]
    rows = []
    for operation_chain in sorted({item.attack_type for item in full_attacks}):
        attacks = [item for item in full_attacks if item.attack_type == operation_chain]
        case_ids = {item.paired_case_id for item in attacks}
        benign = [
            item
            for item in tasks
            if item.defense == "A4 Full AgentGate" and item.case_id in case_ids
        ]
        no_defense = [
            item
            for item in tasks
            if item.defense == "No Defense"
            and item.is_attack
            and item.attack_type == operation_chain
        ]
        rows.append(
            {
                "risk_scenario": _note_value(attacks[0], "risk_type="),
                "operation_chain": operation_chain,
                "attack_tasks": len(attacks),
                "no_defense_attack_success": sum(item.attack_success for item in no_defense),
                "agentgate_prevented": sum(
                    item.attack_prevented_before_side_effect for item in attacks
                ),
                "protection_rate": _rate(
                    sum(item.attack_prevented_before_side_effect for item in attacks),
                    len(attacks),
                ),
                "benign_controls": len(benign),
                "benign_completion_rate": _rate(
                    sum(item.task_success for item in benign),
                    len(benign),
                ),
                "false_negatives": sum(item.attack_success for item in attacks),
                "false_positives": sum(item.blocked for item in benign),
                "matched_rules": "|".join(
                    sorted({rule for item in attacks for rule in item.matched_rules})
                ),
            }
        )
    write_csv(
        root / "tables" / "rq1_risk_scenario_protection.csv",
        rows,
        [
            "risk_scenario",
            "operation_chain",
            "attack_tasks",
            "no_defense_attack_success",
            "agentgate_prevented",
            "protection_rate",
            "benign_controls",
            "benign_completion_rate",
            "false_negatives",
            "false_positives",
            "matched_rules",
        ],
    )


def _build_gateway_confusion_matrix(root: Path, tasks: list[TaskRunRecord]) -> None:
    baseline_attacks = {
        item.case_id
        for item in tasks
        if item.defense == "No Defense" and item.is_attack and item.attack_success
    }
    full = [item for item in tasks if item.defense == "A4 Full AgentGate"]
    slices = {
        "all": full,
        "development": [
            item for item in full if _note_value(item, "evaluation_split=") == "development"
        ],
        "held_out": [
            item for item in full if _note_value(item, "evaluation_split=") == "held_out"
        ],
        "hard_negative": [
            item for item in full if _note_value(item, "hard_negative=") == "true"
        ],
    }
    rows = []
    for name, items in slices.items():
        positives = [
            item for item in items if item.is_attack and item.case_id in baseline_attacks
        ]
        negatives = [item for item in items if not item.is_attack]
        tp = sum(item.attack_prevented_before_side_effect for item in positives)
        fn = sum(item.harmful_side_effect_occurred for item in positives)
        indeterminate = len(positives) - tp - fn
        fp = sum(item.blocked for item in negatives)
        tn = sum(item.task_success and not item.blocked for item in negatives)
        degraded_without_block = len(negatives) - fp - tn
        precision = _rate(tp, tp + fp)
        recall = _rate(tp, tp + fn)
        specificity = _rate(tn, tn + fp)
        fpr = _rate(fp, fp + tn)
        fnr = _rate(fn, fn + tp)
        f1 = _rate(2 * tp, 2 * tp + fp + fn)
        rows.append(
            {
                "slice": name,
                "positive_attack_opportunities": len(positives),
                "negative_benign_controls": len(negatives),
                "tp_pre_effect_controls": tp,
                "fn_harmful_effects": fn,
                "tn_benign_completed": tn,
                "fp_benign_blocked": fp,
                "indeterminate_attacks": indeterminate,
                "degraded_benign_without_block": degraded_without_block,
                "precision": precision,
                "recall_tpr": recall,
                "specificity_tnr": specificity,
                "fpr": fpr,
                "fnr": fnr,
                "f1": f1,
                "mcc": _mcc(tp, tn, fp, fn),
            }
        )
    write_csv(
        root / "tables" / "rq1_gateway_confusion_matrix.csv",
        rows,
        list(rows[0]),
    )


def _mcc(tp: int, tn: int, fp: int, fn: int) -> float:
    denominator = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return (tp * tn - fp * fn) / denominator if denominator else 0.0


def _build_rq2(
    root: Path,
    tasks: list[TaskRunRecord],
    summaries: list[dict[str, Any]],
) -> None:
    fields = [
        "method",
        "asr",
        "defense_success_rate",
        "bcr",
        "paired_benign_fpr",
        "multi_step_attack_total",
        "multi_step_attack_blocked",
        "multi_step_attack_block_rate",
        "provenance_required_attack_total",
        "provenance_required_attack_blocked",
        "provenance_required_block_rate",
        "dependency_edges_constructed",
        "produces_edges",
        "consumes_edges",
        "derives_from_edges",
        "propagated_label_count",
        "max_provenance_depth",
    ]
    rows = []
    for summary in summaries:
        if summary["defense"] == "No Defense":
            continue
        group = [item for item in tasks if item.defense == summary["defense"]]
        attacks = [item for item in group if item.is_attack and item.multi_step]
        provenance = [item for item in attacks if item.requires_provenance]
        benign = [item for item in group if not item.is_attack and item.paired_case_id]
        rows.append(
            {
                "method": summary["defense"],
                "asr": summary["asr"],
                "defense_success_rate": summary["defense_success_rate"],
                "bcr": summary["bcr"],
                "paired_benign_fpr": _rate(sum(item.blocked for item in benign), len(benign)),
                "multi_step_attack_total": len(attacks),
                "multi_step_attack_blocked": sum(item.blocked for item in attacks),
                "multi_step_attack_block_rate": _rate(
                    sum(item.blocked for item in attacks), len(attacks)
                ),
                "provenance_required_attack_total": len(provenance),
                "provenance_required_attack_blocked": sum(item.blocked for item in provenance),
                "provenance_required_block_rate": _rate(
                    sum(item.blocked for item in provenance), len(provenance)
                ),
                "dependency_edges_constructed": sum(
                    item.atg.dependency_edges_constructed for item in group
                ),
                "produces_edges": sum(item.atg.produces_edges for item in group),
                "consumes_edges": sum(item.atg.consumes_edges for item in group),
                "derives_from_edges": sum(item.atg.derives_from_edges for item in group),
                "propagated_label_count": sum(item.atg.propagated_label_count for item in group),
                "max_provenance_depth": max(
                    (item.atg.max_provenance_depth for item in group), default=0
                ),
            }
        )
    write_csv(root / "tables" / "rq2_ablation.csv", rows, fields)

    mode_column = {
        "A0 Event-only": "event_only_blocked",
        "A1 Event + Sequence": "sequence_blocked",
        "A2 ATG without Provenance": "atg_no_provenance_blocked",
        "A3 ATG + Provenance without Labels": "atg_provenance_no_labels_blocked",
        "A4 Full AgentGate": "full_blocked",
    }
    patterns: dict[str, dict[str, Any]] = defaultdict(dict)
    for item in tasks:
        if not item.is_attack or item.defense not in mode_column:
            continue
        row = patterns[item.attack_type]
        row["risk_pattern"] = item.attack_type
        row["cases"] = row.get("cases", 0) + (1 if item.defense == "A4 Full AgentGate" else 0)
        column = mode_column[item.defense]
        row[column] = row.get(column, 0) + int(item.blocked)
    pattern_fields = ["risk_pattern", "cases", *mode_column.values()]
    write_csv(
        root / "tables" / "rq2_stateful_patterns.csv",
        [patterns[key] for key in sorted(patterns)],
        pattern_fields,
    )


def _ensure_model_table_schemas(root: Path) -> None:
    robustness_path = root / "tables" / "rq5_model_robustness.csv"
    if not robustness_path.exists():
        write_csv(
            robustness_path,
            [],
            [
                "semantic_model",
                "runs",
                "asr",
                "bcr",
                "fpr",
                "fnr",
                "precision",
                "recall",
                "f1",
                "semantic_extraction_success_rate",
                "schema_failure_rate",
                "api_success_rate",
                "total_tokens",
                "p50_latency_ms",
                "p95_latency_ms",
                "p99_latency_ms",
            ],
        )
    agreement_path = root / "tables" / "rq5_model_agreement.csv"
    if not agreement_path.exists():
        write_csv(
            agreement_path,
            [],
            ["model_a", "model_b", "cases", "decision_agreement", "cohen_kappa"],
        )
    disagreement_path = root / "failures" / "rq5_disagreement_cases.jsonl"
    if not disagreement_path.exists():
        write_jsonl(disagreement_path, [])


def _write_failure_cases(root: Path, tasks: list[TaskRunRecord]) -> None:
    full = [item for item in tasks if item.defense == "A4 Full AgentGate"]
    write_jsonl(
        root / "failures" / "false_positive_cases.jsonl",
        [item for item in full if not item.is_attack and item.blocked],
    )
    write_jsonl(
        root / "failures" / "false_negative_cases.jsonl",
        [item for item in full if item.is_attack and item.attack_success],
    )
    write_jsonl(
        root / "failures" / "late_detection_cases.jsonl",
        [item for item in full if item.late_detection],
    )
    semantic_path = root / "raw" / "semantic_runs.jsonl"
    semantic = read_jsonl(semantic_path) if semantic_path.exists() else []
    write_jsonl(
        root / "failures" / "semantic_resolution_failures.jsonl",
        [item for item in semantic if not item.get("semantic_success", False)],
    )
    write_jsonl(root / "failures" / "dependency_resolution_failures.jsonl", [])


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the AgentGate end-to-end RQ tables")
    parser.add_argument("--output-root", default="evaluation/results")
    args = parser.parse_args()
    build_tables(args.output_root)


if __name__ == "__main__":
    main()
