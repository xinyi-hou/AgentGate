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
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Build unified public end-to-end result table")
    parser.add_argument("--output-root", default="evaluation/results")
    args = parser.parse_args()
    rows = build_public_table(args.output_root)
    print(f"wrote {len(rows)} public benchmark rows")


if __name__ == "__main__":
    main()
