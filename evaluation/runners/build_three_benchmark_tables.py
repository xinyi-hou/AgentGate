from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict
from pathlib import Path
from typing import Any

from evaluation.recording import read_jsonl, write_csv, write_jsonl

DEFENSE_FILES = {
    "No Defense": "no_defense",
    "AgentGate": "agentgate",
    "Tool Filter": "tool_filter",
    "AgentSpec": "agentspec",
    "Invariant Guardrails": "invariant",
}


def build_tables(output_root: str | Path = "evaluation/results") -> list[dict[str, Any]]:
    root = Path(output_root)
    rows = []
    rows.extend(_agentdojo_rows(root))
    rows.extend(_agent_safetybench_rows(root))
    rows.extend(_statefulbench_rows(root))
    fields = [
        "benchmark",
        "defense",
        "positive_tasks",
        "completed_positive_tasks",
        "comparison_positive_tasks",
        "attack_successes_all",
        "asr_all",
        "no_defense_opportunities",
        "attack_successes_on_opportunities",
        "asr_on_opportunities",
        "intervention_supported_preventions",
        "prevention_rate",
        "prevention_rate_ci95",
        "negative_tasks",
        "completed_negative_tasks",
        "comparison_negative_tasks",
        "benign_successes",
        "bcr",
        "bcr_ci95",
        "false_positive_tasks",
        "fpr",
        "fpr_ci95",
        "precision",
        "recall",
        "specificity",
        "mcc",
        "error_tasks",
    ]
    write_csv(root / "tables/rq1_three_benchmark_baselines_v2.csv", rows, fields)
    write_jsonl(root / "normalized/three_benchmark_baselines_v2.jsonl", rows)
    scenario_rows = _scenario_rows(root)
    write_csv(
        root / "tables/rq1_risk_scenario_baselines_v2.csv",
        scenario_rows,
        [
            "benchmark",
            "scenario",
            "defense",
            "positive_tasks",
            "attack_successes",
            "asr",
            "negative_tasks",
            "benign_successes",
            "bcr",
        ],
    )
    return rows


def _agentdojo_rows(root: Path) -> list[dict[str, Any]]:
    groups = {}
    for label, slug in DEFENSE_FILES.items():
        path = root / f"normalized/agentdojo_{slug}_tool_effect_subset_v2.jsonl"
        if path.exists():
            groups[label] = read_jsonl(path)
    baseline = {row["case_id"]: row for row in groups.get("No Defense", [])}
    core_groups = {
        defense: records
        for defense, records in groups.items()
        if defense != "Tool Filter"
    }
    core_common_cases = _common_completed_case_ids(core_groups, "case_id")
    rows = []
    for defense, records in groups.items():
        comparison_cases = set(core_common_cases)
        if defense == "Tool Filter":
            comparison_cases &= {
                item["case_id"]
                for item in records
                if item.get("status") != "error"
            }
        opportunities = {
            case_id
            for case_id, row in baseline.items()
            if row["label"] == "positive"
            and row["status"] == "completed"
            and row["successful_sink_executed"]
            and case_id in comparison_cases
        }
        rows.append(
            _public_row(
                benchmark="AgentDojo",
                defense=defense,
                records=records,
                opportunities=opportunities,
                comparison_case_ids=comparison_cases,
                attack_success=lambda item: bool(item["successful_sink_executed"]),
                benign_success=lambda item: bool(item["utility"]),
                intervened=lambda item, current_defense=defense: (
                    item["blocked_calls"] > 0
                    or (
                        current_defense == "Tool Filter"
                        and item.get("filter_removed_tools", 0) > 0
                    )
                ),
            )
        )
    return rows


def _agent_safetybench_rows(root: Path) -> list[dict[str, Any]]:
    groups = {}
    for label, slug in DEFENSE_FILES.items():
        if slug == "tool_filter":
            continue
        path = root / f"normalized/agent_safetybench_{slug}_tool_effect_subset_v2.jsonl"
        if path.exists():
            groups[label] = read_jsonl(path)
    baseline = {
        row["evaluation_case_id"]: row for row in groups.get("No Defense", [])
    }
    common_cases = _common_completed_case_ids(groups, "evaluation_case_id")
    opportunities = {
        case_id
        for case_id, row in baseline.items()
        if row["evaluation_label"] == "positive"
        and row["status"] != "error"
        and row["successful_sink_executed"]
        and case_id in common_cases
    }
    return [
        _public_row(
            benchmark="Agent-SafetyBench",
            defense=defense,
            records=records,
            opportunities=opportunities,
            comparison_case_ids=common_cases,
            case_id_key="evaluation_case_id",
            label_key="evaluation_label",
            attack_success=lambda item: bool(item["successful_sink_executed"]),
            benign_success=lambda item: bool(item["objective_task_success"]),
            intervened=lambda item: item["blocked_calls"] > 0,
        )
        for defense, records in groups.items()
    ]


def _statefulbench_rows(root: Path) -> list[dict[str, Any]]:
    path = root / "raw/statefulbench_tasks.jsonl"
    if not path.exists():
        return []
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in read_jsonl(path):
        groups[row["defense"]].append(row)
    baseline = {row["case_id"]: row for row in groups.get("No Defense", [])}
    compared_groups = {
        defense: records
        for defense, records in groups.items()
        if defense
        in {
            "No Defense",
            "A4 Full AgentGate",
            "AgentSpec",
            "Invariant Guardrails",
        }
    }
    common_cases = _common_completed_case_ids(compared_groups, "case_id")
    opportunities = {
        case_id
        for case_id, row in baseline.items()
        if row["is_attack"]
        and row["harmful_side_effect_occurred"]
        and case_id in common_cases
    }
    included = {
        "No Defense",
        "A4 Full AgentGate",
        "AgentSpec",
        "Invariant Guardrails",
    }
    return [
        _public_row(
            benchmark="StatefulBench v4",
            defense="AgentGate" if defense == "A4 Full AgentGate" else defense,
            records=records,
            opportunities=opportunities,
            comparison_case_ids=common_cases,
            label_key="is_attack",
            positive_value=True,
            attack_success=lambda item: bool(item["attack_success"]),
            benign_success=lambda item: bool(item["task_success"]),
            intervened=lambda item: bool(item["blocked"]),
        )
        for defense, records in groups.items()
        if defense in included
    ]


def _public_row(
    *,
    benchmark: str,
    defense: str,
    records: list[dict[str, Any]],
    opportunities: set[str],
    comparison_case_ids: set[str] | None = None,
    attack_success,
    benign_success,
    intervened,
    case_id_key: str = "case_id",
    label_key: str = "label",
    positive_value: Any = "positive",
) -> dict[str, Any]:
    positives = [item for item in records if item[label_key] == positive_value]
    negatives = [item for item in records if item[label_key] != positive_value]
    completed_positive = [item for item in positives if item.get("status") != "error"]
    completed_negative = [item for item in negatives if item.get("status") != "error"]
    comparison_positive = [
        item
        for item in completed_positive
        if comparison_case_ids is None or item[case_id_key] in comparison_case_ids
    ]
    comparison_negative = [
        item
        for item in completed_negative
        if comparison_case_ids is None or item[case_id_key] in comparison_case_ids
    ]
    opportunity_rows = [
        item for item in comparison_positive if item[case_id_key] in opportunities
    ]
    attack_count = sum(attack_success(item) for item in comparison_positive)
    opportunity_attacks = sum(attack_success(item) for item in opportunity_rows)
    prevented = sum(
        not attack_success(item) and intervened(item) for item in opportunity_rows
    )
    benign_count = sum(benign_success(item) for item in comparison_negative)
    false_positives = sum(intervened(item) for item in comparison_negative)
    false_negatives = len(opportunity_rows) - prevented
    true_negatives = len(comparison_negative) - false_positives
    return {
        "benchmark": benchmark,
        "defense": defense,
        "positive_tasks": len(positives),
        "completed_positive_tasks": len(completed_positive),
        "comparison_positive_tasks": len(comparison_positive),
        "attack_successes_all": attack_count,
        "asr_all": _ratio(attack_count, len(comparison_positive)),
        "no_defense_opportunities": len(opportunities),
        "attack_successes_on_opportunities": opportunity_attacks,
        "asr_on_opportunities": _ratio(opportunity_attacks, len(opportunity_rows)),
        "intervention_supported_preventions": prevented,
        "prevention_rate": _ratio(prevented, len(opportunity_rows)),
        "prevention_rate_ci95": _wilson_interval(prevented, len(opportunity_rows)),
        "negative_tasks": len(negatives),
        "completed_negative_tasks": len(completed_negative),
        "comparison_negative_tasks": len(comparison_negative),
        "benign_successes": benign_count,
        "bcr": _ratio(benign_count, len(comparison_negative)),
        "bcr_ci95": _wilson_interval(benign_count, len(comparison_negative)),
        "false_positive_tasks": false_positives,
        "fpr": _ratio(false_positives, len(comparison_negative)),
        "fpr_ci95": _wilson_interval(false_positives, len(comparison_negative)),
        "precision": _ratio(prevented, prevented + false_positives),
        "recall": _ratio(prevented, prevented + false_negatives),
        "specificity": _ratio(true_negatives, true_negatives + false_positives),
        "mcc": _mcc(prevented, false_positives, true_negatives, false_negatives),
        "error_tasks": sum(item.get("status") == "error" for item in records),
    }


def _common_completed_case_ids(
    groups: dict[str, list[dict[str, Any]]],
    case_id_key: str,
) -> set[str]:
    completed = [
        {
            item[case_id_key]
            for item in records
            if item.get("status") != "error"
        }
        for records in groups.values()
    ]
    return set.intersection(*completed) if completed else set()


def _scenario_rows(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    sources = []
    for label, slug in DEFENSE_FILES.items():
        if slug != "tool_filter":
            path = root / f"normalized/agent_safetybench_{slug}_tool_effect_subset_v2.jsonl"
            if path.exists():
                sources.extend(("Agent-SafetyBench", label, item) for item in read_jsonl(path))
    stateful_path = root / "raw/statefulbench_tasks.jsonl"
    if stateful_path.exists():
        sources.extend(
            (
                "StatefulBench v4",
                "AgentGate"
                if item["defense"] == "A4 Full AgentGate"
                else item["defense"],
                item,
            )
            for item in read_jsonl(stateful_path)
            if item["defense"]
            in {
                "No Defense",
                "A4 Full AgentGate",
                "AgentSpec",
                "Invariant Guardrails",
            }
        )
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for benchmark, defense, item in sources:
        scenario = item["risks"][0] if benchmark == "Agent-SafetyBench" else _risk(item)
        groups[(benchmark, scenario, defense)].append(item)
    for (benchmark, scenario, defense), items in sorted(groups.items()):
        if benchmark == "Agent-SafetyBench":
            positives = [item for item in items if item["evaluation_label"] == "positive"]
            negatives = [item for item in items if item["evaluation_label"] == "negative"]
            attacks = sum(item["successful_sink_executed"] for item in positives)
            benign = sum(bool(item["objective_task_success"]) for item in negatives)
        else:
            positives = [item for item in items if item["is_attack"]]
            negatives = [item for item in items if not item["is_attack"]]
            attacks = sum(item["attack_success"] for item in positives)
            benign = sum(item["task_success"] for item in negatives)
        rows.append(
            {
                "benchmark": benchmark,
                "scenario": scenario,
                "defense": defense,
                "positive_tasks": len(positives),
                "attack_successes": attacks,
                "asr": _ratio(attacks, len(positives)),
                "negative_tasks": len(negatives),
                "benign_successes": benign,
                "bcr": _ratio(benign, len(negatives)),
            }
        )
    return rows


def _risk(item: dict[str, Any]) -> str:
    for note in item.get("notes", []):
        if note.startswith("risk_type="):
            return note.split("=", 1)[1]
    return item.get("attack_type", "unknown")


def _ratio(numerator: int, denominator: int) -> float | str:
    return round(numerator / denominator, 6) if denominator else ""


def _mcc(tp: int, fp: int, tn: int, fn: int) -> float | str:
    denominator = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    if denominator == 0:
        return ""
    return round((tp * tn - fp * fn) / math.sqrt(denominator), 6)


def _wilson_interval(successes: int, trials: int, z: float = 1.959963984540054) -> str:
    if trials == 0:
        return ""
    probability = successes / trials
    denominator = 1 + z**2 / trials
    center = (probability + z**2 / (2 * trials)) / denominator
    margin = (
        z
        * math.sqrt(
            probability * (1 - probability) / trials + z**2 / (4 * trials**2)
        )
        / denominator
    )
    return f"{max(0.0, center - margin):.6f},{min(1.0, center + margin):.6f}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Build three-benchmark baseline tables")
    parser.add_argument("--output-root", default="evaluation/results")
    args = parser.parse_args()
    rows = build_tables(args.output_root)
    print(json.dumps(rows, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
