from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from evaluation.recording import read_jsonl, write_csv


def _rate(numerator: int, denominator: int) -> float | str:
    return numerator / denominator if denominator else ""


def _agentdojo_rows(root: Path) -> list[dict[str, Any]]:
    rows = []
    result_sets: dict[str, list[dict[str, Any]]] = {}
    for defense_slug in ("no_defense", "agentgate"):
        path = root / "normalized" / f"agentdojo_{defense_slug}_full.jsonl"
        if path.exists():
            result_sets[defense_slug] = read_jsonl(path)

    baseline_records = result_sets.get("no_defense", [])
    baseline_solvable_ids = {
        item["case_id"]
        for item in baseline_records
        if item["status"] == "completed" and item["injection_task_solvable"]
    }
    for defense_slug in ("no_defense", "agentgate"):
        records = result_sets.get(defense_slug)
        if not records:
            continue
        completed = [item for item in records if item["status"] == "completed"]
        common_solvable = [
            item for item in completed if item["case_id"] in baseline_solvable_ids
        ]
        attacks = sum(bool(item["attack_success"]) for item in completed)
        common_attacks = sum(bool(item["attack_success"]) for item in common_solvable)
        utility = sum(bool(item["utility"]) for item in completed)
        rows.append(
            {
                "benchmark": "AgentDojo v1.2",
                "defense": records[0]["defense"] if records else defense_slug,
                "scope": "all four suites; tool_knowledge attack",
                "tasks": len(records),
                "completed": len(completed),
                "applicable_tasks": len(completed),
                "safety_denominator": len(completed),
                "unsafe_or_attack_successes": attacks,
                "unsafe_or_attack_success_rate": _rate(attacks, len(completed)),
                "applicable_safety_denominator": len(common_solvable),
                "applicable_unsafe_or_attack_successes": common_attacks,
                "applicable_unsafe_or_attack_success_rate": _rate(
                    common_attacks, len(common_solvable)
                ),
                "utility_denominator": len(completed),
                "utility_successes": utility,
                "utility_rate": _rate(utility, len(completed)),
                "tasks_with_block": sum(bool(item["blocked_calls"]) for item in completed),
                "scorer": (
                    "official AgentDojo utility/security evaluators; secondary denominator "
                    "is the fixed no-defense-solvable subset"
                ),
            }
        )
    return rows


def _agent_safetybench_rows(root: Path) -> list[dict[str, Any]]:
    rows = []
    for defense_slug in ("no_defense", "agentgate"):
        execution_path = root / "normalized" / f"agent_safetybench_{defense_slug}.jsonl"
        score_path = (
            root
            / "normalized"
            / f"agent_safetybench_{defense_slug}_api_scores.jsonl"
        )
        if not execution_path.exists() or not score_path.exists():
            continue
        executions = read_jsonl(execution_path)
        scores = read_jsonl(score_path)
        execution_by_id = {str(item["id"]): item for item in executions}
        valid_scores = [item for item in scores if item["status"] == "completed"]
        applicable_scores = [
            item
            for item in valid_scores
            if execution_by_id.get(str(item["id"]), {}).get("applicable_to_agentgate", False)
        ]
        unsafe = sum(item["label"] == "unsafe" for item in valid_scores)
        applicable_unsafe = sum(item["label"] == "unsafe" for item in applicable_scores)
        completed = [item for item in executions if item["status"] != "error"]
        applicable = [item for item in executions if item["applicable_to_agentgate"]]
        rows.append(
            {
                "benchmark": "Agent-SafetyBench",
                "defense": scores[0]["defense"] if scores else defense_slug,
                "scope": "all 2,000 released tasks; eight risk categories",
                "tasks": len(executions),
                "completed": len(completed),
                "applicable_tasks": len(applicable),
                "safety_denominator": len(valid_scores),
                "unsafe_or_attack_successes": unsafe,
                "unsafe_or_attack_success_rate": _rate(unsafe, len(valid_scores)),
                "applicable_safety_denominator": len(applicable_scores),
                "applicable_unsafe_or_attack_successes": applicable_unsafe,
                "applicable_unsafe_or_attack_success_rate": _rate(
                    applicable_unsafe, len(applicable_scores)
                ),
                "utility_denominator": "",
                "utility_successes": "",
                "utility_rate": "",
                "tasks_with_block": sum(bool(item["blocked_calls"]) for item in applicable),
                "scorer": "API rubric judge (not official ShieldAgent scorer)",
            }
        )
    return rows


def build_public_table(output_root: str | Path = "evaluation/results") -> list[dict[str, Any]]:
    root = Path(output_root)
    rows = [*_agentdojo_rows(root), *_agent_safetybench_rows(root)]
    write_csv(
        root / "tables" / "rq1_public_end_to_end.csv",
        rows,
        [
            "benchmark",
            "defense",
            "scope",
            "tasks",
            "completed",
            "applicable_tasks",
            "safety_denominator",
            "unsafe_or_attack_successes",
            "unsafe_or_attack_success_rate",
            "applicable_safety_denominator",
            "applicable_unsafe_or_attack_successes",
            "applicable_unsafe_or_attack_success_rate",
            "utility_denominator",
            "utility_successes",
            "utility_rate",
            "tasks_with_block",
            "scorer",
        ],
    )
    _build_attribution_table(root)
    return rows


def _build_attribution_table(root: Path) -> list[dict[str, Any]]:
    rows = [*_agentdojo_attribution(root), *_agent_safetybench_attribution(root)]
    fields = [
        "benchmark",
        "scope",
        "paired_tasks",
        "baseline_positive_opportunities",
        "outcome_improvements",
        "improvements_with_gateway_intervention",
        "improvements_without_gateway_intervention",
        "residual_unsafe_or_attack_success",
        "safe_to_unsafe_regressions",
        "tasks_with_gateway_intervention",
        "attribution_limit",
    ]
    write_csv(root / "tables" / "rq1_public_attribution.csv", rows, fields)
    return rows


def _agentdojo_attribution(root: Path) -> list[dict[str, Any]]:
    no_defense = root / "normalized" / "agentdojo_no_defense_full.jsonl"
    agentgate = root / "normalized" / "agentdojo_agentgate_full.jsonl"
    if not no_defense.exists() or not agentgate.exists():
        return []
    nd = {item["case_id"]: item for item in read_jsonl(no_defense) if item["status"] == "completed"}
    ag = {item["case_id"]: item for item in read_jsonl(agentgate) if item["status"] == "completed"}
    pairs = [(nd[key], ag[key]) for key in sorted(nd.keys() & ag.keys())]
    positives = [(left, right) for left, right in pairs if bool(left["attack_success"])]
    improved = [pair for pair in positives if not bool(pair[1]["attack_success"])]
    return [
        {
            "benchmark": "AgentDojo v1.2",
            "scope": "paired completed trajectories",
            "paired_tasks": len(pairs),
            "baseline_positive_opportunities": len(positives),
            "outcome_improvements": len(improved),
            "improvements_with_gateway_intervention": sum(
                bool(right.get("blocked_calls", 0)) for _, right in improved
            ),
            "improvements_without_gateway_intervention": sum(
                not bool(right.get("blocked_calls", 0)) for _, right in improved
            ),
            "residual_unsafe_or_attack_success": sum(
                bool(right["attack_success"]) for _, right in positives
            ),
            "safe_to_unsafe_regressions": sum(
                not bool(left["attack_success"]) and bool(right["attack_success"])
                for left, right in pairs
            ),
            "tasks_with_gateway_intervention": sum(
                bool(right.get("blocked_calls", 0)) for _, right in pairs
            ),
            "attribution_limit": (
                "An intervention is any denied call, not proof that the denied call was the "
                "benchmark harmful sink; independent agent trajectories remain non-causal."
            ),
        }
    ]


def _agent_safetybench_attribution(root: Path) -> list[dict[str, Any]]:
    nd_scores_path = root / "normalized" / "agent_safetybench_no_defense_api_scores.jsonl"
    ag_scores_path = root / "normalized" / "agent_safetybench_agentgate_api_scores.jsonl"
    ag_exec_path = root / "normalized" / "agent_safetybench_agentgate.jsonl"
    if not nd_scores_path.exists() or not ag_scores_path.exists() or not ag_exec_path.exists():
        return []
    nd = {
        str(item["id"]): item
        for item in read_jsonl(nd_scores_path)
        if item["status"] == "completed"
    }
    ag = {
        str(item["id"]): item
        for item in read_jsonl(ag_scores_path)
        if item["status"] == "completed"
    }
    executions = {str(item["id"]): item for item in read_jsonl(ag_exec_path)}
    output = []
    scopes = (
        ("all paired judged tasks", False),
        ("tool-applicable paired tasks", True),
    )
    for scope, applicable_only in scopes:
        ids = sorted(nd.keys() & ag.keys())
        if applicable_only:
            ids = [
                key
                for key in ids
                if executions.get(key, {}).get("applicable_to_agentgate", False)
            ]
        pairs = [(nd[key], ag[key], executions.get(key, {})) for key in ids]
        positives = [pair for pair in pairs if pair[0]["label"] == "unsafe"]
        improved = [pair for pair in positives if pair[1]["label"] == "safe"]
        output.append(
            {
                "benchmark": "Agent-SafetyBench",
                "scope": scope,
                "paired_tasks": len(pairs),
                "baseline_positive_opportunities": len(positives),
                "outcome_improvements": len(improved),
                "improvements_with_gateway_intervention": sum(
                    bool(execution.get("blocked_calls", 0)) for _, _, execution in improved
                ),
                "improvements_without_gateway_intervention": sum(
                    not bool(execution.get("blocked_calls", 0)) for _, _, execution in improved
                ),
                "residual_unsafe_or_attack_success": sum(
                    right["label"] == "unsafe" for _, right, _ in positives
                ),
                "safe_to_unsafe_regressions": sum(
                    left["label"] == "safe" and right["label"] == "unsafe"
                    for left, right, _ in pairs
                ),
                "tasks_with_gateway_intervention": sum(
                    bool(execution.get("blocked_calls", 0)) for _, _, execution in pairs
                ),
                "attribution_limit": (
                    "API dialogue-judge labels and independent trajectories do not identify "
                    "a concrete harmful sink; intervention-supported changes are not causal TP."
                ),
            }
        )
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description="Build unified public end-to-end result table")
    parser.add_argument("--output-root", default="evaluation/results")
    args = parser.parse_args()
    rows = build_public_table(args.output_root)
    print(f"wrote {len(rows)} public benchmark rows")


if __name__ == "__main__":
    main()
