from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path
from statistics import mean
from typing import Any

from evaluation.metrics import summarize, wilson_interval
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
    agentdojo_path = root / "normalized" / "agentdojo_tasks.jsonl"
    agentdojo_tasks = (
        [TaskRunRecord.model_validate(item) for item in read_jsonl(agentdojo_path)]
        if agentdojo_path.exists()
        else []
    )
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
    for defense in sorted({item.defense for item in agentdojo_tasks}):
        matching = [item for item in agentdojo_tasks if item.defense == defense]
        successes = sum(item.attack_success for item in matching)
        low, high = wilson_interval(successes, len(matching))
        security_rows.append(
            {
                "benchmark": "AgentDojo",
                "defense": defense,
                "attack_total": len(matching),
                "attack_success_count": successes,
                "attack_blocked_count": sum(item.blocked for item in matching),
                "asr": _rate(successes, len(matching)),
                "asr_ci_low": low,
                "asr_ci_high": high,
                "defense_success_rate": 1 - _rate(successes, len(matching)),
                "harmful_side_effect_count": sum(
                    item.harmful_side_effect_occurred for item in matching
                ),
                "attack_prevented_before_side_effect_count": sum(
                    item.attack_prevented_before_side_effect for item in matching
                ),
                "late_detection_count": sum(item.late_detection for item in matching),
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
    for defense in sorted({item.defense for item in agentdojo_tasks}):
        matching = [item for item in agentdojo_tasks if item.defense == defense]
        successes = sum(item.task_success for item in matching)
        low, high = wilson_interval(successes, len(matching))
        utility_rows.append(
            {
                "benchmark": "AgentDojo",
                "defense": defense,
                "benign_task_total": len(matching),
                "benign_task_success_count": successes,
                "bcr": _rate(successes, len(matching)),
                "bcr_ci_low": low,
                "bcr_ci_high": high,
                "benign_blocked_count": sum(item.blocked for item in matching),
                "benign_degraded_count": sum(not item.task_success for item in matching),
                "mean_tool_calls": mean(item.tool_calls for item in matching),
                "mean_turns": mean(item.turns for item in matching),
                "mean_trajectory_length": mean(item.trajectory_length for item in matching),
            }
        )
    write_csv(root / "tables" / "rq1_benign_utility.csv", utility_rows, utility_fields)

    _build_rq1_risk_scenarios(root, tasks)
    _build_rq2(root, tasks, summaries)
    _build_rq3(root, tasks, principal, agentdojo_tasks)
    _write_unavailable_table_schemas(root)
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
            "matched_rules",
        ],
    )


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


def _build_rq3(
    root: Path,
    tasks: list[TaskRunRecord],
    summaries: list[dict[str, Any]],
    agentdojo_tasks: list[TaskRunRecord],
) -> None:
    fields = [
        "benchmark",
        "method",
        "asr",
        "defense_success_rate",
        "bcr",
        "false_block_rate",
        "harmful_side_effect_rate",
        "late_detection_rate",
        "tool_call_success_rate",
        "average_tool_calls",
        "average_turns",
        "mean_end_to_end_latency_ms",
    ]
    rows = []
    for summary in summaries:
        group = [item for item in tasks if item.defense == summary["defense"]]
        attacks = [item for item in group if item.is_attack]
        calls = sum(item.tool_calls for item in group)
        rows.append(
            {
                "benchmark": summary["benchmark"],
                "method": summary["defense"],
                "asr": summary["asr"],
                "defense_success_rate": summary["defense_success_rate"],
                "bcr": summary["bcr"],
                "false_block_rate": summary["false_block_rate"],
                "harmful_side_effect_rate": _rate(
                    sum(item.harmful_side_effect_occurred for item in attacks), len(attacks)
                ),
                "late_detection_rate": _rate(
                    sum(item.late_detection for item in attacks), len(attacks)
                ),
                "tool_call_success_rate": _rate(
                    sum(item.tool_call_successes for item in group), calls
                ),
                "average_tool_calls": mean(item.tool_calls for item in group),
                "average_turns": mean(item.turns for item in group),
                "mean_end_to_end_latency_ms": mean(item.end_to_end_latency_ms for item in group),
            }
        )
    for defense in sorted({item.defense for item in agentdojo_tasks}):
        group = [item for item in agentdojo_tasks if item.defense == defense]
        calls = sum(item.tool_calls for item in group)
        rows.append(
            {
                "benchmark": "AgentDojo",
                "method": defense,
                "asr": mean(item.attack_success for item in group),
                "defense_success_rate": 1 - mean(item.attack_success for item in group),
                "bcr": mean(item.task_success for item in group),
                "false_block_rate": mean(not item.task_success for item in group),
                "harmful_side_effect_rate": mean(
                    item.harmful_side_effect_occurred for item in group
                ),
                "late_detection_rate": mean(item.late_detection for item in group),
                "tool_call_success_rate": _rate(
                    sum(item.tool_call_successes for item in group), calls
                ),
                "average_tool_calls": mean(item.tool_calls for item in group),
                "average_turns": mean(item.turns for item in group),
                "mean_end_to_end_latency_ms": mean(item.end_to_end_latency_ms for item in group),
            }
        )
    write_csv(root / "tables" / "rq3_baseline_comparison.csv", rows, fields)


def _write_unavailable_table_schemas(root: Path) -> None:
    write_csv(
        root / "tables" / "rq2_external_stateful_baselines.csv",
        [
            {
                "benchmark": "MSB",
                "baseline": "AgentGuard / Invariant / MCPKernel / AgentGate",
                "applicable_cases": 0,
                "status": "not_run",
                "reason": "Paper Search MCP requires interactive Smithery OAuth.",
            },
            {
                "benchmark": "MCP-SafetyBench",
                "baseline": "AgentGuard / Invariant / MCPKernel / AgentGate",
                "applicable_cases": 0,
                "status": "not_run",
                "reason": "Disposable accounts and complete service credentials were unavailable.",
            },
        ],
        ["benchmark", "baseline", "applicable_cases", "asr", "bcr", "status", "reason"],
    )
    write_csv(
        root / "tables" / "rq3_mcpbench_utility.csv",
        [
            {
                "method": "No Defense / AgentGuard / Invariant / MCPKernel / AgentGate",
                "tasks": 0,
                "status": "not_run",
                "reason": "Required model, judge, and MCP server credentials were unavailable.",
            }
        ],
        [
            "method",
            "tasks",
            "task_completion_rate",
            "tool_selection_score",
            "parameter_correctness",
            "planning_task_score",
            "status",
            "reason",
        ],
    )
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
