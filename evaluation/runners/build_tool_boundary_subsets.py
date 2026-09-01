from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from agentdojo.task_suite.load_suites import get_suite

from evaluation.recording import write_csv, write_jsonl

AGENTDOJO_POSITIVES = 60
AGENTDOJO_NEGATIVES = 97
AGENT_SAFETYBENCH_POSITIVES = 256
AGENT_SAFETYBENCH_NEGATIVES = 256
AGENT_SAFETYBENCH_RISKS = {
    "Compromise availability",
    "Lead to property loss",
    "Leak sensitive data / information",
}


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _environment_signature(record: dict[str, Any]) -> tuple[tuple[str, tuple[str, ...]], ...]:
    return tuple(
        sorted(
            (
                str(environment.get("name", "")),
                tuple(sorted(str(tool) for tool in environment.get("tools", []))),
            )
            for environment in record.get("environments", [])
            if environment.get("name")
        )
    )


def _environment_names(record: dict[str, Any]) -> set[str]:
    return {name for name, _ in _environment_signature(record)}


def _tool_names(record: dict[str, Any]) -> set[str]:
    return {
        tool
        for _, tools in _environment_signature(record)
        for tool in tools
    }


def _match_score(positive: dict[str, Any], negative: dict[str, Any]) -> tuple[int, int, int, int]:
    positive_signature = _environment_signature(positive)
    negative_signature = _environment_signature(negative)
    shared_tools = len(_tool_names(positive) & _tool_names(negative))
    shared_environments = len(_environment_names(positive) & _environment_names(negative))
    return (
        int(positive_signature == negative_signature),
        shared_tools,
        shared_environments,
        -abs(int(positive["id"]) - int(negative["id"])),
    )


def build_agentdojo(root: Path) -> list[dict[str, Any]]:
    baseline_path = root / "evaluation/results/normalized/agentdojo_no_defense_full.jsonl"
    baseline = _load_jsonl(baseline_path)
    positives = [
        row
        for row in baseline
        if row.get("status") == "completed" and row.get("attack_success") is True
    ]
    if len(positives) != AGENTDOJO_POSITIVES:
        raise ValueError(
            f"Expected {AGENTDOJO_POSITIVES} AgentDojo baseline successes, "
            f"found {len(positives)}"
        )

    rows: list[dict[str, Any]] = []
    for row in sorted(
        positives,
        key=lambda item: (item["suite"], item["user_task"], item["injection_task"]),
    ):
        rows.append(
            {
                "benchmark": "AgentDojo",
                "sample_id": row["case_id"],
                "source_case_id": row["case_id"],
                "label": "positive",
                "is_attack": True,
                "suite": row["suite"],
                "user_task": row["user_task"],
                "injection_task": row["injection_task"],
                "pair_id": None,
                "paired_case_id": None,
                "selection_basis": (
                    "Frozen no-defense baseline attack_success=true under the official "
                    "AgentDojo security scorer."
                ),
                "tool_boundary_requirement": "official injected end-to-end task",
                "source_path": str(baseline_path.relative_to(root)),
            }
        )

    clean_tasks = []
    for suite_name in ("workspace", "travel", "banking", "slack"):
        suite = get_suite("v1.2", suite_name)
        clean_tasks.extend((suite_name, task_id) for task_id in sorted(suite.user_tasks))
    if len(clean_tasks) != AGENTDOJO_NEGATIVES:
        raise ValueError(
            f"Expected {AGENTDOJO_NEGATIVES} AgentDojo clean tasks, found {len(clean_tasks)}"
        )
    for suite_name, task_id in clean_tasks:
        sample_id = f"{suite_name}::{task_id}::clean"
        rows.append(
            {
                "benchmark": "AgentDojo",
                "sample_id": sample_id,
                "source_case_id": sample_id,
                "label": "negative",
                "is_attack": False,
                "suite": suite_name,
                "user_task": task_id,
                "injection_task": None,
                "pair_id": None,
                "paired_case_id": None,
                "selection_basis": "All official v1.2 user tasks executed without injection.",
                "tool_boundary_requirement": "official clean end-to-end task",
                "source_path": "AgentDojo benchmark v1.2 task suite",
            }
        )
    return rows


def build_agent_safetybench(root: Path) -> list[dict[str, Any]]:
    released_path = (
        root / "benchmarks/e2e/agent_safetybench/data/released_data.json"
    )
    execution_path = (
        root / "evaluation/results/normalized/agent_safetybench_no_defense.jsonl"
    )
    score_path = (
        root
        / "evaluation/results/normalized/agent_safetybench_no_defense_api_scores.jsonl"
    )
    records = {
        int(record["id"]): record
        for record in json.loads(released_path.read_text(encoding="utf-8"))
    }
    executions = {int(row["id"]): row for row in _load_jsonl(execution_path)}
    scores = {int(score["id"]): score for score in _load_jsonl(score_path)}
    candidates = [
        record
        for record in records.values()
        if record["risks"][0] in AGENT_SAFETYBENCH_RISKS
        and executions[int(record["id"])]["tool_calls"] > 0
        and executions[int(record["id"])]["status"] != "error"
        and scores[int(record["id"])]["status"] == "completed"
    ]
    positives = [
        record for record in candidates if scores[int(record["id"])]["label"] == "unsafe"
    ]
    negative_pool = [
        record for record in candidates if scores[int(record["id"])]["label"] == "safe"
    ]
    if len(positives) != AGENT_SAFETYBENCH_POSITIVES:
        raise ValueError(
            f"Expected {AGENT_SAFETYBENCH_POSITIVES} unsafe tool trajectories, "
            f"found {len(positives)}"
        )
    if len(negative_pool) < AGENT_SAFETYBENCH_NEGATIVES:
        raise ValueError(
            f"Need {AGENT_SAFETYBENCH_NEGATIVES} safe tool trajectories, "
            f"found {len(negative_pool)}"
        )

    unused = {int(record["id"]): record for record in negative_pool}
    pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for positive in sorted(positives, key=lambda item: (item["risks"][0], int(item["id"]))):
        same_risk = [
            negative
            for negative in unused.values()
            if negative["risks"][0] == positive["risks"][0]
        ]
        if not same_risk:
            raise ValueError(f"No unused same-risk negative for case {positive['id']}")
        negative = max(
            same_risk,
            key=lambda item: (_match_score(positive, item), -int(item["id"])),
        )
        unused.pop(int(negative["id"]))
        pairs.append((positive, negative))

    rows: list[dict[str, Any]] = []
    for pair_number, (positive, negative) in enumerate(pairs, 1):
        pair_id = f"asb-pair-{pair_number:03d}"
        for record, label in ((positive, "positive"), (negative, "negative")):
            counterpart = negative if label == "positive" else positive
            case_id = int(record["id"])
            rows.append(
                {
                    "benchmark": "Agent-SafetyBench",
                    "sample_id": f"agent-safetybench::{case_id}",
                    "source_case_id": case_id,
                    "label": label,
                    "is_attack": label == "positive",
                    "risk": record["risks"][0],
                    "pair_id": pair_id,
                    "paired_case_id": int(counterpart["id"]),
                    "generated_tool_calls": executions[case_id]["tool_calls"],
                    "environment_signature": _environment_signature(record),
                    "selection_basis": (
                        "Frozen no-defense trajectory with a real structured tool call and "
                        + (
                            "unsafe API-rubric outcome."
                            if label == "positive"
                            else (
                                "safe API-rubric outcome, matched one-to-one by risk, tool, "
                                "and environment."
                            )
                        )
                    ),
                    "tool_boundary_requirement": "generated structured tool call",
                    "source_path": str(released_path.relative_to(root)),
                    "execution_path": str(execution_path.relative_to(root)),
                    "score_path": str(score_path.relative_to(root)),
                }
            )
    return rows


def _validate(rows: list[dict[str, Any]]) -> None:
    counts = Counter((row["benchmark"], row["label"]) for row in rows)
    expected = {
        ("AgentDojo", "positive"): AGENTDOJO_POSITIVES,
        ("AgentDojo", "negative"): AGENTDOJO_NEGATIVES,
        ("Agent-SafetyBench", "positive"): AGENT_SAFETYBENCH_POSITIVES,
        ("Agent-SafetyBench", "negative"): AGENT_SAFETYBENCH_NEGATIVES,
    }
    if counts != expected:
        raise ValueError(f"Unexpected subset counts: {counts}; expected {expected}")
    sample_ids = [row["sample_id"] for row in rows]
    if len(sample_ids) != len(set(sample_ids)):
        raise ValueError("Subset contains duplicate sample IDs")


def build_subsets(
    *, repository_root: str | Path = ".", output_root: str | Path = "evaluation/results"
) -> list[dict[str, Any]]:
    root = Path(repository_root).resolve()
    output = Path(output_root)
    rows = [*build_agentdojo(root), *build_agent_safetybench(root)]
    _validate(rows)
    write_jsonl(output / "manifests/tool_boundary_public_subset.jsonl", rows)
    counts = Counter((row["benchmark"], row["label"]) for row in rows)
    summary = [
        {"benchmark": benchmark, "label": label, "tasks": count}
        for (benchmark, label), count in sorted(counts.items())
    ]
    write_csv(
        output / "tables/tool_boundary_public_subset_summary.csv",
        summary,
        ["benchmark", "label", "tasks"],
    )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Freeze tool-boundary public evaluation subsets")
    parser.add_argument("--repository-root", default=".")
    parser.add_argument("--output-root", default="evaluation/results")
    args = parser.parse_args()
    rows = build_subsets(
        repository_root=args.repository_root,
        output_root=args.output_root,
    )
    print(f"wrote {len(rows)} frozen public subset records")


if __name__ == "__main__":
    main()
