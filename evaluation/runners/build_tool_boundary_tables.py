from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from evaluation.recording import read_jsonl, write_csv


def _rate(numerator: int, denominator: int) -> float | str:
    return numerator / denominator if denominator else ""


def _manifest(root: Path) -> list[dict[str, Any]]:
    return read_jsonl(root / "manifests/tool_boundary_public_subset.jsonl")


def _agentdojo_rows(root: Path, manifest: list[dict[str, Any]]) -> list[dict[str, Any]]:
    expected = {
        str(row["sample_id"]): row
        for row in manifest
        if row["benchmark"] == "AgentDojo"
    }
    rows = []
    for defense_slug in ("no_defense", "agentgate"):
        path = root / f"normalized/agentdojo_{defense_slug}_tool_boundary_subset.jsonl"
        if not path.exists():
            continue
        records = [row for row in read_jsonl(path) if row.get("status") == "completed"]
        positives = [row for row in records if expected[row["case_id"]]["label"] == "positive"]
        negatives = [row for row in records if expected[row["case_id"]]["label"] == "negative"]
        attacks = sum(bool(row["attack_success"]) for row in positives)
        blocked_positive = sum(bool(row["blocked_calls"]) for row in positives)
        blocked_negative = sum(bool(row["blocked_calls"]) for row in negatives)
        benign_completed = sum(bool(row["utility"]) for row in negatives)
        rows.append(
            {
                "benchmark": "AgentDojo",
                "defense": records[0]["defense"] if records else defense_slug,
                "positive_expected": 60,
                "positive_completed": len(positives),
                "unsafe_or_attack_success": attacks,
                "unsafe_or_attack_rate": _rate(attacks, len(positives)),
                "positive_with_intervention": blocked_positive,
                "negative_expected": 97,
                "negative_completed": len(negatives),
                "negative_with_intervention": blocked_negative,
                "negative_intervention_rate": _rate(blocked_negative, len(negatives)),
                "benign_completed": benign_completed,
                "benign_completion_rate": _rate(benign_completed, len(negatives)),
                "negative_semantics": "official clean user tasks",
            }
        )
    return rows


def _agentdojo_attribution(root: Path, manifest: list[dict[str, Any]]) -> list[dict[str, Any]]:
    no_defense_path = root / "normalized/agentdojo_no_defense_tool_boundary_subset.jsonl"
    agentgate_path = root / "normalized/agentdojo_agentgate_tool_boundary_subset.jsonl"
    if not no_defense_path.exists() or not agentgate_path.exists():
        return []
    labels = {
        str(row["sample_id"]): row["label"]
        for row in manifest
        if row["benchmark"] == "AgentDojo"
    }
    no_defense = {
        row["case_id"]: row
        for row in read_jsonl(no_defense_path)
        if row.get("status") == "completed"
    }
    agentgate = {
        row["case_id"]: row
        for row in read_jsonl(agentgate_path)
        if row.get("status") == "completed"
    }
    ids = sorted(no_defense.keys() & agentgate.keys())
    positive_ids = [case_id for case_id in ids if labels[case_id] == "positive"]
    negative_ids = [case_id for case_id in ids if labels[case_id] == "negative"]
    opportunities = [
        case_id for case_id in positive_ids if no_defense[case_id]["attack_success"]
    ]
    prevented_with_control = sum(
        not agentgate[case_id]["attack_success"]
        and bool(agentgate[case_id]["blocked_calls"])
        for case_id in opportunities
    )
    safe_without_control = sum(
        not agentgate[case_id]["attack_success"]
        and not bool(agentgate[case_id]["blocked_calls"])
        for case_id in opportunities
    )
    return [
        {
            "benchmark": "AgentDojo",
            "paired_positive_tasks": len(positive_ids),
            "baseline_reproduced_attack_success": sum(
                bool(no_defense[case_id]["attack_success"]) for case_id in positive_ids
            ),
            "agentgate_prevented_with_control": prevented_with_control,
            "agentgate_safe_without_control": safe_without_control,
            "agentgate_residual_attack_success": sum(
                bool(agentgate[case_id]["attack_success"]) for case_id in opportunities
            ),
            "positive_regressions": sum(
                not bool(no_defense[case_id]["attack_success"])
                and bool(agentgate[case_id]["attack_success"])
                for case_id in positive_ids
            ),
            "paired_negative_tasks": len(negative_ids),
            "negative_interventions": sum(
                bool(agentgate[case_id]["blocked_calls"]) for case_id in negative_ids
            ),
            "negative_task_failures": sum(
                not bool(agentgate[case_id]["utility"]) for case_id in negative_ids
            ),
            "causal_limit": (
                "A denied call is runtime control evidence, but AgentDojo does not label the "
                "specific harmful sink; safe outcomes without control are not credited "
                "to AgentGate."
            ),
        }
    ]


def _agent_safetybench_rows(
    root: Path, manifest: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    expected = {
        str(row["source_case_id"]): row
        for row in manifest
        if row["benchmark"] == "Agent-SafetyBench"
    }
    rows = []
    for defense_slug in ("no_defense", "agentgate"):
        execution_path = (
            root
            / f"normalized/agent_safetybench_{defense_slug}_tool_boundary_subset_v1.jsonl"
        )
        score_path = (
            root
            / "normalized"
            / f"agent_safetybench_{defense_slug}_tool_boundary_subset_v1_api_scores.jsonl"
        )
        if not execution_path.exists() or not score_path.exists():
            continue
        executions = {
            str(row["id"]): row
            for row in read_jsonl(execution_path)
            if row.get("status") != "error"
        }
        scores = {
            str(row["id"]): row
            for row in read_jsonl(score_path)
            if row.get("status") == "completed"
        }
        ids = sorted(expected.keys() & executions.keys() & scores.keys(), key=int)
        positive_ids = [case_id for case_id in ids if expected[case_id]["label"] == "positive"]
        negative_ids = [case_id for case_id in ids if expected[case_id]["label"] == "negative"]
        unsafe_positive = sum(scores[case_id]["label"] == "unsafe" for case_id in positive_ids)
        unsafe_negative = sum(scores[case_id]["label"] == "unsafe" for case_id in negative_ids)
        rows.append(
            {
                "benchmark": "Agent-SafetyBench",
                "defense": scores[ids[0]]["defense"] if ids else defense_slug,
                "positive_expected": 256,
                "positive_completed": len(positive_ids),
                "unsafe_or_attack_success": unsafe_positive,
                "unsafe_or_attack_rate": _rate(unsafe_positive, len(positive_ids)),
                "positive_with_intervention": sum(
                    bool(executions[case_id]["blocked_calls"]) for case_id in positive_ids
                ),
                "negative_expected": 256,
                "negative_completed": len(negative_ids),
                "negative_with_intervention": sum(
                    bool(executions[case_id]["blocked_calls"]) for case_id in negative_ids
                ),
                "negative_intervention_rate": _rate(
                    sum(bool(executions[case_id]["blocked_calls"]) for case_id in negative_ids),
                    len(negative_ids),
                ),
                "benign_completed": len(negative_ids) - unsafe_negative,
                "benign_completion_rate": _rate(
                    len(negative_ids) - unsafe_negative, len(negative_ids)
                ),
                "negative_semantics": (
                    "matched baseline-safe tool trajectories; not ordinary benign prompts"
                ),
            }
        )
    return rows


def _agent_safetybench_attribution(
    root: Path, manifest: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    nd_score_path = (
        root / "normalized/agent_safetybench_no_defense_tool_boundary_subset_v1_api_scores.jsonl"
    )
    ag_score_path = (
        root / "normalized/agent_safetybench_agentgate_tool_boundary_subset_v1_api_scores.jsonl"
    )
    ag_execution_path = (
        root / "normalized/agent_safetybench_agentgate_tool_boundary_subset_v1.jsonl"
    )
    if not all(path.exists() for path in (nd_score_path, ag_score_path, ag_execution_path)):
        return []
    labels = {
        str(row["source_case_id"]): row["label"]
        for row in manifest
        if row["benchmark"] == "Agent-SafetyBench"
    }
    nd = {
        str(row["id"]): row
        for row in read_jsonl(nd_score_path)
        if row.get("status") == "completed"
    }
    ag = {
        str(row["id"]): row
        for row in read_jsonl(ag_score_path)
        if row.get("status") == "completed"
    }
    executions = {str(row["id"]): row for row in read_jsonl(ag_execution_path)}
    ids = sorted(nd.keys() & ag.keys() & executions.keys(), key=int)
    positive_ids = [case_id for case_id in ids if labels[case_id] == "positive"]
    negative_ids = [case_id for case_id in ids if labels[case_id] == "negative"]
    opportunities = [case_id for case_id in positive_ids if nd[case_id]["label"] == "unsafe"]
    improved = [
        case_id
        for case_id in opportunities
        if ag[case_id]["label"] == "safe"
    ]
    return [
        {
            "benchmark": "Agent-SafetyBench",
            "paired_positive_tasks": len(positive_ids),
            "baseline_reproduced_attack_success": sum(
                nd[case_id]["label"] == "unsafe" for case_id in positive_ids
            ),
            "agentgate_prevented_with_control": sum(
                bool(executions[case_id]["blocked_calls"]) for case_id in improved
            ),
            "agentgate_safe_without_control": sum(
                not bool(executions[case_id]["blocked_calls"]) for case_id in improved
            ),
            "agentgate_residual_attack_success": sum(
                ag[case_id]["label"] == "unsafe" for case_id in opportunities
            ),
            "positive_regressions": sum(
                nd[case_id]["label"] == "safe" and ag[case_id]["label"] == "unsafe"
                for case_id in positive_ids
            ),
            "paired_negative_tasks": len(negative_ids),
            "negative_interventions": sum(
                bool(executions[case_id]["blocked_calls"]) for case_id in negative_ids
            ),
            "negative_task_failures": sum(
                ag[case_id]["label"] == "unsafe" for case_id in negative_ids
            ),
            "causal_limit": (
                "The API rubric scores complete dialogue behavior and does not identify a concrete "
                "harmful sink; only improvements accompanied by control are intervention-supported."
            ),
        }
    ]


def build_tables(output_root: str | Path = "evaluation/results") -> list[dict[str, Any]]:
    root = Path(output_root)
    manifest = _manifest(root)
    result_rows = [
        *_agentdojo_rows(root, manifest),
        *_agent_safetybench_rows(root, manifest),
    ]
    fields = [
        "benchmark",
        "defense",
        "positive_expected",
        "positive_completed",
        "unsafe_or_attack_success",
        "unsafe_or_attack_rate",
        "positive_with_intervention",
        "negative_expected",
        "negative_completed",
        "negative_with_intervention",
        "negative_intervention_rate",
        "benign_completed",
        "benign_completion_rate",
        "negative_semantics",
    ]
    write_csv(root / "tables/rq1_tool_boundary_subset.csv", result_rows, fields)
    attribution = [
        *_agentdojo_attribution(root, manifest),
        *_agent_safetybench_attribution(root, manifest),
    ]
    write_csv(
        root / "tables/rq1_tool_boundary_attribution.csv",
        attribution,
        [
            "benchmark",
            "paired_positive_tasks",
            "baseline_reproduced_attack_success",
            "agentgate_prevented_with_control",
            "agentgate_safe_without_control",
            "agentgate_residual_attack_success",
            "positive_regressions",
            "paired_negative_tasks",
            "negative_interventions",
            "negative_task_failures",
            "causal_limit",
        ],
    )
    return result_rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Build frozen tool-boundary subset tables")
    parser.add_argument("--output-root", default="evaluation/results")
    args = parser.parse_args()
    rows = build_tables(args.output_root)
    print(f"wrote {len(rows)} tool-boundary result rows")


if __name__ == "__main__":
    main()
