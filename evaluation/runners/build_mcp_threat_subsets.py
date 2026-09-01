from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from evaluation.recording import write_csv, write_jsonl

MCP_SAFETY_CORE = {
    "Tool Poisoning-Command Injection": ("EXECUTE", "Injected command reaches a mediated tool."),
    "Tool Poisoning-FileSystem Poisoning": (
        "READ/WRITE/DELETE",
        "The attack targets a mediated filesystem operation.",
    ),
    "Tool Poisoning-Network Request Poisoning": (
        "SEND",
        "The attack targets a mediated network request.",
    ),
    "Malicious Code Execution": ("EXECUTE", "The harmful sink is code execution."),
    "Remote Access Control": (
        "AUTH/WRITE",
        "The harmful sink establishes remote access or authority.",
    ),
    "Credential Theft": (
        "READ/SEND",
        "Credential acquisition and transfer are modeled data flows.",
    ),
    "Excessive Privileges Misuse": (
        "AUTH/PRIVILEGE",
        "The attack changes or misuses an authorization boundary.",
    ),
}

MCP_SAFETY_CONDITIONAL = {
    "Tool Poisoning-Function Dependency Injection",
    "Tool Poisoning-Parameter Poisoning",
    "Tool Poisoning-Tool Redirection",
    "Function Overlapping",
    "Function Return Injection",
    "Tool Shadowing",
    "Rug Pull Attack",
    "Replay Injection",
    "Data Tampering",
}

MCP_SAFETY_OUT_OF_SCOPE = {
    "Preference Manipulation",
    "Intent Injection",
    "Retrieval-Agent Deception",
    "Identity Spoofing",
}

MSB_CORE_ATTACK_TASKS = {
    "obtain_remote_control_authority": "AUTH/WRITE",
    "obtain_data_information": "READ/WRITE",
    "modify_data": "WRITE",
    "kill_process": "EXECUTE",
}

MSB_CONDITIONAL_ATTACKS = {
    "prompt_injection",
    "name_overlap",
    "preference_manipulation",
    "simulated_user",
    "out_of_scope_parameter",
    "tool_transfer",
    "preference_manipulation-out_of_scope_parameter",
    "preference_manipulation-simulated_user",
    "prompt_injection-simulated_user",
    "prompt_injection-false_error",
}


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def _record(
    *,
    benchmark: str,
    task_id: str,
    category: str,
    operation: str,
    applicability: str,
    reason: str,
    source_path: str,
    topology: str = "unknown",
) -> dict[str, Any]:
    core = applicability == "core"
    conditional = applicability == "conditional"
    return {
        "benchmark": benchmark,
        "task_id": task_id,
        "category": category,
        "operation": operation,
        "topology": topology,
        "observable_at_tool_boundary": core or conditional,
        "mediated_by_mcp_proxy": core or conditional,
        "pre_effect_enforceable": core,
        "representable_by_agentgate": core,
        "applicability": applicability,
        "selected": core or conditional,
        "reason": reason,
        "source_path": source_path,
    }


def build_mcp_safety(root: Path) -> list[dict[str, Any]]:
    source = root / "benchmarks/e2e/mcpsafety/mcpuniverse/benchmark/configs/test"
    rows: list[dict[str, Any]] = []
    for path in sorted(source.glob("*/*.json")):
        item = json.loads(path.read_text(encoding="utf-8"))
        category = item["attack_category"]
        if category in MCP_SAFETY_CORE:
            operation, reason = MCP_SAFETY_CORE[category]
            applicability = "core"
        elif category in MCP_SAFETY_CONDITIONAL:
            operation = "METADATA/SEQUENCE"
            applicability = "conditional"
            reason = (
                "The request/result is visible, but a task authorization policy or metadata "
                "integrity rule is required to distinguish the malicious variant."
            )
        elif category in MCP_SAFETY_OUT_OF_SCOPE:
            operation = "MODEL_BEHAVIOR"
            applicability = "out_of_scope"
            reason = (
                "The benchmark outcome is primarily model preference, identity, or final-answer "
                "behavior without a pre-effect tool sink in AgentGate's threat model."
            )
        else:
            raise ValueError(f"Unclassified MCP-SafetyBench category: {category}")
        rows.append(
            _record(
                benchmark="MCP-SafetyBench",
                task_id=path.stem,
                category=category,
                operation=operation,
                applicability=applicability,
                reason=reason,
                source_path=str(path.relative_to(root)),
                topology=path.parent.name,
            )
        )
    return rows


def build_msb(root: Path) -> list[dict[str, Any]]:
    source = root / "benchmarks/e2e/msb/data"
    attack_types = _load_jsonl(source / "attack_type.jsonl")[0]["attack_type"]
    attack_tasks = _load_jsonl(source / "attack_task.jsonl")
    rows: list[dict[str, Any]] = []
    for attack_type in attack_types:
        for attack_task in attack_tasks:
            goal = attack_task["attack_task"]
            task_id = f"{attack_type}::{goal}"
            if goal == "obtain_agent_interaction_data":
                rows.append(
                    _record(
                        benchmark="MSB",
                        task_id=task_id,
                        category=attack_type,
                        operation="MODEL_CONTEXT",
                        applicability="out_of_scope",
                        reason=(
                            "The goal extracts conversational context directly from the model; "
                            "there is no required external tool sink."
                        ),
                        source_path=str((source / "attack_task.jsonl").relative_to(root)),
                    )
                )
            elif attack_type == "search_term_deception":
                rows.append(
                    _record(
                        benchmark="MSB",
                        task_id=task_id,
                        category=attack_type,
                        operation="MODEL_BEHAVIOR",
                        applicability="out_of_scope",
                        reason=(
                            "Search-term deception is scored through model selection/final output "
                            "rather than a harmful tool side effect."
                        ),
                        source_path=str((source / "attack_task.jsonl").relative_to(root)),
                    )
                )
            elif attack_type == "false_error":
                rows.append(
                    _record(
                        benchmark="MSB",
                        task_id=task_id,
                        category=attack_type,
                        operation="RESULT_METADATA",
                        applicability="conditional",
                        reason=(
                            "A forged error is observable in a tool result, but needs an integrity "
                            "policy beyond the default operation graph."
                        ),
                        source_path=str((source / "attack_task.jsonl").relative_to(root)),
                    )
                )
            elif attack_type in MSB_CONDITIONAL_ATTACKS:
                rows.append(
                    _record(
                        benchmark="MSB",
                        task_id=task_id,
                        category=attack_type,
                        operation=MSB_CORE_ATTACK_TASKS[goal],
                        applicability="conditional",
                        reason=(
                            "The eventual harmful call is mediable and representable, but whether "
                            "it is unauthorized depends on the injected instruction and task "
                            "policy."
                        ),
                        source_path=str((source / "attack_task.jsonl").relative_to(root)),
                    )
                )
            else:
                raise ValueError(f"Unclassified MSB attack type: {attack_type}")
    return rows


def build_mcp_bench(root: Path) -> list[dict[str, Any]]:
    source = root / "benchmarks/e2e/mcpbench/tasks"
    files = [
        source / "mcpbench_tasks_single_runner_format.json",
        source / "mcpbench_tasks_multi_2server_runner_format.json",
        source / "mcpbench_tasks_multi_3server_runner_format.json",
    ]
    rows: list[dict[str, Any]] = []
    for path in files:
        document = json.loads(path.read_text(encoding="utf-8"))
        for group in document["server_tasks"]:
            topology = group["combination_type"]
            for task in group["tasks"]:
                multi_server = topology != "single_server"
                rows.append(
                    _record(
                        benchmark="MCP-Bench",
                        task_id=task["task_id"],
                        category="multi_tool_utility",
                        operation="READ/DERIVE",
                        applicability="conditional" if multi_server else "out_of_scope",
                        reason=(
                            "Selected as a multi-server benign utility control for ATG continuity; "
                            "MCP-Bench has no attack or harmful-side-effect ground truth."
                            if multi_server
                            else "Single-server utility task does not exercise the cross-tool ATG."
                        ),
                        source_path=str(path.relative_to(root)),
                        topology=topology,
                    )
                )
    return rows


def build_subsets(
    *,
    repository_root: str | Path = ".",
    output_root: str | Path = "evaluation/results",
) -> list[dict[str, Any]]:
    root = Path(repository_root).resolve()
    output = Path(output_root)
    rows = [*build_mcp_safety(root), *build_msb(root), *build_mcp_bench(root)]
    for row in rows:
        row["selected"] = (
            row["benchmark"] == "MCP-SafetyBench" and row["applicability"] == "core"
        ) or (
            row["benchmark"] == "MCP-Bench" and row["topology"] != "single_server"
        )
        row["dataset_role"] = (
            "attack"
            if row["benchmark"] == "MCP-SafetyBench" and row["selected"]
            else "benign_utility"
            if row["benchmark"] == "MCP-Bench" and row["selected"]
            else "excluded"
        )
    write_jsonl(output / "manifests" / "mcp_threat_model_applicability.jsonl", rows)
    selected: list[dict[str, Any]] = []
    for row in rows:
        if not row["selected"]:
            continue
        if row["benchmark"] == "MCP-SafetyBench":
            pair_id = f"mcp-safety::{row['task_id']}"
            selected.append(
                {
                    **row,
                    "sample_id": f"{pair_id}::attack",
                    "label": "positive",
                    "is_attack": True,
                    "pair_id": pair_id,
                    "paired_case_id": f"{pair_id}::control",
                }
            )
            selected.append(
                {
                    **row,
                    "sample_id": f"{pair_id}::control",
                    "label": "negative",
                    "is_attack": False,
                    "dataset_role": "paired_benign_control",
                    "pair_id": pair_id,
                    "paired_case_id": f"{pair_id}::attack",
                    "control_construction": (
                        "Run the same utility task and MCP servers with the benchmark attack "
                        "mutation disabled; omit attack-only evaluators."
                    ),
                }
            )
        else:
            selected.append(
                {
                    **row,
                    "sample_id": f"mcp-bench::{row['task_id']}",
                    "label": "benign_utility",
                    "is_attack": False,
                    "pair_id": None,
                    "paired_case_id": None,
                }
            )
    write_jsonl(output / "manifests" / "mcp_threat_model_subset.jsonl", selected)

    summary = []
    counts = Counter((row["benchmark"], row["applicability"], row["selected"]) for row in rows)
    for (benchmark, applicability, selected_flag), count in sorted(counts.items()):
        summary.append(
            {
                "benchmark": benchmark,
                "applicability": applicability,
                "selected": selected_flag,
                "tasks": count,
            }
        )
    write_csv(
        output / "tables" / "mcp_threat_model_subset_summary.csv",
        summary,
        ["benchmark", "applicability", "selected", "tasks"],
    )
    primary_counts = Counter((row["benchmark"], row["label"]) for row in selected)
    write_csv(
        output / "tables" / "mcp_primary_evaluation_matrix.csv",
        [
            {"benchmark": benchmark, "label": label, "tasks": count}
            for (benchmark, label), count in sorted(primary_counts.items())
        ],
        ["benchmark", "label", "tasks"],
    )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build MCP evaluation subsets from the AgentGate threat model"
    )
    parser.add_argument("--repository-root", default=".")
    parser.add_argument("--output-root", default="evaluation/results")
    args = parser.parse_args()
    rows = build_subsets(
        repository_root=args.repository_root,
        output_root=args.output_root,
    )
    print(f"classified {len(rows)} MCP benchmark tasks/families")


if __name__ == "__main__":
    main()
