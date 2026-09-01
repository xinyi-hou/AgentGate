from __future__ import annotations

import argparse
import json
import os
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Literal

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, get_llm, load_system_message
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.tool_execution import (
    ToolsExecutionLoop,
    ToolsExecutor,
)
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import (
    benchmark_suite_with_injections,
    benchmark_suite_without_injections,
)
from agentdojo.logging import OutputLogger
from agentdojo.task_suite.load_suites import get_suite

from evaluation.adapters.agentdojo_agentgate import AgentGateToolsExecutor
from evaluation.recording import git_revision, write_csv, write_jsonl

Defense = Literal["agentgate", "no_defense"]
SUITES = ("workspace", "travel", "banking", "slack")


def _checkpoint_path(
    output_root: Path,
    defense: Defense,
    model_id: str,
    suite_name: str,
    user_task: str,
    injection_task: str | None,
) -> Path:
    return (
        output_root
        / "checkpoints"
        / "agentdojo"
        / defense
        / model_id.replace("/", "_")
        / "tool_boundary_subset_v1"
        / suite_name
        / f"{user_task}__{injection_task or 'clean'}.json"
    )


def _run_pair(payload: dict[str, Any]) -> dict[str, Any]:
    suite_name = payload["suite_name"]
    user_task = payload["user_task"]
    injection_task: str | None = payload["injection_task"]
    model_id = payload["model_id"]
    defense: Defense = payload["defense"]
    output_root = Path(payload["output_root"])
    checkpoint = _checkpoint_path(
        output_root,
        defense,
        model_id,
        suite_name,
        user_task,
        injection_task,
    )
    if checkpoint.exists():
        return json.loads(checkpoint.read_text(encoding="utf-8"))

    if os.getenv("LLM_URL"):
        os.environ.setdefault("OPENAI_COMPATIBLE_BASE_URL", os.environ["LLM_URL"])
    if os.getenv("LLM_API"):
        os.environ.setdefault("OPENAI_COMPATIBLE_API_KEY", os.environ["LLM_API"])
    llm = get_llm("openai-compatible", "openai-compatible", model_id, "tool")
    records: list[dict[str, Any]] = []
    if defense == "agentgate":
        tool_executor = AgentGateToolsExecutor(
            output_root
            / "raw"
            / "agentdojo"
            / "audit"
            / suite_name
            / user_task
            / (injection_task or "clean")
        )
    else:
        tool_executor = ToolsExecutor()
    pipeline = AgentPipeline(
        [
            SystemMessage(load_system_message(None)),
            InitQuery(),
            llm,
            ToolsExecutionLoop([tool_executor, llm]),
        ]
    )
    pipeline.name = f"openai-compatible-{defense}"
    suite = get_suite("v1.2", suite_name)
    logdir = (
        output_root
        / "raw"
        / "agentdojo"
        / "runs"
        / defense
        / suite_name
        / user_task
        / (injection_task or "clean")
    )
    with OutputLogger(str(logdir)):
        if injection_task is None:
            results = benchmark_suite_without_injections(
                pipeline,
                suite,
                user_tasks=[user_task],
                logdir=logdir,
                force_rerun=True,
                benchmark_version="v1.2",
            )
        else:
            attacker = load_attack("tool_knowledge", suite, pipeline)
            results = benchmark_suite_with_injections(
                pipeline,
                suite,
                attacker,
                user_tasks=[user_task],
                injection_tasks=[injection_task],
                logdir=logdir,
                force_rerun=True,
                benchmark_version="v1.2",
            )
    if isinstance(tool_executor, AgentGateToolsExecutor):
        records = [
            item
            for item in tool_executor.records
            if item["user_task_id"] == user_task
            and (
                injection_task is None
                or item["injection_task_id"] == injection_task
            )
        ]
    result_key = (user_task, injection_task or "")
    row = {
        "benchmark": "AgentDojo",
        "benchmark_commit": git_revision("benchmarks/e2e/agentdojo"),
        "benchmark_version": "0.1.35/v1.2",
        "suite": suite_name,
        "user_task": user_task,
        "injection_task": injection_task,
        "case_id": f"{suite_name}::{user_task}::{injection_task or 'clean'}",
        "attack": "tool_knowledge" if injection_task else "none",
        "is_attack": injection_task is not None,
        "label": "positive" if injection_task else "negative",
        "defense": "AgentGate" if defense == "agentgate" else "No Defense",
        "agent_model": model_id,
        "utility": bool(results["utility_results"][result_key]),
        "attack_success": (
            bool(results["security_results"][result_key]) if injection_task else False
        ),
        "injection_task_solvable": (
            bool(results["injection_tasks_utility_results"][injection_task])
            if injection_task
            else None
        ),
        "tool_calls": len(records),
        "blocked_calls": sum(not item["executed"] for item in records),
        "status": "completed",
        "calls": records,
    }
    checkpoint.parent.mkdir(parents=True, exist_ok=True)
    checkpoint.write_text(json.dumps(row, ensure_ascii=False, indent=2), encoding="utf-8")
    return row


def _run_pair_safe(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        return _run_pair(payload)
    except Exception as exc:
        return {
            "benchmark": "AgentDojo",
            "suite": payload["suite_name"],
            "user_task": payload["user_task"],
            "injection_task": payload["injection_task"],
            "case_id": (
                f"{payload['suite_name']}::{payload['user_task']}::"
                f"{payload['injection_task'] or 'clean'}"
            ),
            "attack": "tool_knowledge" if payload["injection_task"] else "none",
            "is_attack": payload["injection_task"] is not None,
            "label": "positive" if payload["injection_task"] else "negative",
            "defense": ("AgentGate" if payload["defense"] == "agentgate" else "No Defense"),
            "agent_model": payload["model_id"],
            "status": "error",
            "error": f"{type(exc).__name__}: {exc}",
            "utility": False,
            "attack_success": False,
            "injection_task_solvable": False,
            "tool_calls": 0,
            "blocked_calls": 0,
            "calls": [],
        }


def _all_pairs(suites: list[str]) -> list[tuple[str, str, str]]:
    pairs = []
    for suite_name in suites:
        suite = get_suite("v1.2", suite_name)
        pairs.extend(
            (suite_name, user_task, injection_task)
            for user_task in suite.user_tasks
            for injection_task in suite.injection_tasks
        )
    return pairs


def run_agentdojo_full(
    *,
    model_id: str,
    defense: Defense,
    output_root: str | Path,
    suites: list[str] | None = None,
    workers: int = 8,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    output_root = Path(output_root)
    selected_suites = suites or list(SUITES)
    pairs = _all_pairs(selected_suites)
    if limit is not None:
        pairs = pairs[:limit]
    payloads = [
        {
            "suite_name": suite_name,
            "user_task": user_task,
            "injection_task": injection_task,
            "model_id": model_id,
            "defense": defense,
            "output_root": str(output_root),
        }
        for suite_name, user_task, injection_task in pairs
    ]
    records: list[dict[str, Any]] = []
    if workers == 1:
        for index, payload in enumerate(payloads, 1):
            records.append(_run_pair_safe(payload))
            print(f"AgentDojo {defense}: {index}/{len(payloads)}")
    else:
        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(_run_pair_safe, payload) for payload in payloads]
            for index, future in enumerate(as_completed(futures), 1):
                records.append(future.result())
                if index % 25 == 0 or index == len(futures):
                    print(f"AgentDojo {defense}: {index}/{len(futures)}")
    records.sort(key=lambda item: (item["suite"], item["user_task"], item["injection_task"]))
    write_jsonl(
        output_root / "normalized" / f"agentdojo_{defense}_full.jsonl",
        records,
    )
    summary = []
    for suite_name in [*selected_suites, "ALL"]:
        group = (
            records
            if suite_name == "ALL"
            else [item for item in records if item["suite"] == suite_name]
        )
        completed = [item for item in group if item["status"] == "completed"]
        solvable = [item for item in completed if item["injection_task_solvable"]]
        summary.append(
            {
                "suite": suite_name,
                "defense": "AgentGate" if defense == "agentgate" else "No Defense",
                "tasks": len(group),
                "completed": len(completed),
                "defense_conditioned_solvable_tasks": len(solvable),
                "attack_successes": sum(item["attack_success"] for item in completed),
                "asr_all": (
                    sum(item["attack_success"] for item in completed) / len(completed)
                    if completed
                    else ""
                ),
                "asr_defense_conditioned_solvable": (
                    sum(item["attack_success"] for item in solvable) / len(solvable)
                    if solvable
                    else ""
                ),
                "utility_successes": sum(item["utility"] for item in completed),
                "utility_rate": (
                    sum(item["utility"] for item in completed) / len(completed) if completed else ""
                ),
                "tasks_with_block": sum(item["blocked_calls"] > 0 for item in completed),
            }
        )
    write_csv(
        output_root / "tables" / f"agentdojo_{defense}_full.csv",
        summary,
        [
            "suite",
            "defense",
            "tasks",
            "completed",
            "defense_conditioned_solvable_tasks",
            "attack_successes",
            "asr_all",
            "asr_defense_conditioned_solvable",
            "utility_successes",
            "utility_rate",
            "tasks_with_block",
        ],
    )
    return records


def run_agentdojo_subset(
    *,
    manifest_path: str | Path,
    model_id: str,
    defense: Defense,
    output_root: str | Path,
    workers: int = 8,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    output_root = Path(output_root)
    manifest = [
        json.loads(line)
        for line in Path(manifest_path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    selected = [row for row in manifest if row["benchmark"] == "AgentDojo"]
    if limit is not None:
        selected = selected[:limit]
    payloads = [
        {
            "suite_name": row["suite"],
            "user_task": row["user_task"],
            "injection_task": row["injection_task"],
            "model_id": model_id,
            "defense": defense,
            "output_root": str(output_root),
        }
        for row in selected
    ]
    records: list[dict[str, Any]] = []
    if workers == 1:
        for index, payload in enumerate(payloads, 1):
            records.append(_run_pair_safe(payload))
            print(f"AgentDojo subset {defense}: {index}/{len(payloads)}")
    else:
        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(_run_pair_safe, payload) for payload in payloads]
            for index, future in enumerate(as_completed(futures), 1):
                records.append(future.result())
                if index % 25 == 0 or index == len(futures):
                    print(f"AgentDojo subset {defense}: {index}/{len(futures)}")
    records.sort(key=lambda item: (item["label"], item["suite"], item["case_id"]))
    write_jsonl(
        output_root / "normalized" / f"agentdojo_{defense}_tool_boundary_subset.jsonl",
        records,
    )
    return records


def run_agentdojo(
    *,
    suite_name: str,
    user_task: str,
    injection_task: str,
    model_id: str,
    output_root: str | Path,
    defense: Defense = "agentgate",
) -> dict[str, Any]:
    row = _run_pair(
        {
            "suite_name": suite_name,
            "user_task": user_task,
            "injection_task": injection_task,
            "model_id": model_id,
            "defense": defense,
            "output_root": str(output_root),
        }
    )
    write_jsonl(
        Path(output_root) / "normalized" / f"agentdojo_{defense}.jsonl",
        [row],
    )
    return row


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run AgentDojo end to end through AgentGate's tool boundary"
    )
    parser.add_argument("--suite", action="append", dest="suites")
    parser.add_argument("--user-task", default="user_task_0")
    parser.add_argument("--injection-task", default="injection_task_0")
    parser.add_argument("--model-id", default=os.getenv("LLM_MODEL_3", "DeepSeek-V4-Pro-0813"))
    parser.add_argument("--defense", choices=["agentgate", "no_defense"], default="agentgate")
    parser.add_argument("--output-root", default="evaluation/results")
    parser.add_argument("--all", action="store_true", help="Run every v1.2 suite/task pair.")
    parser.add_argument(
        "--manifest",
        help="Run the frozen AgentDojo records in a tool-boundary subset manifest.",
    )
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    if args.manifest:
        rows = run_agentdojo_subset(
            manifest_path=args.manifest,
            model_id=args.model_id,
            defense=args.defense,
            output_root=args.output_root,
            workers=args.workers,
            limit=args.limit,
        )
        print(f"completed {len(rows)} AgentDojo subset tasks")
    elif args.all:
        rows = run_agentdojo_full(
            model_id=args.model_id,
            defense=args.defense,
            output_root=args.output_root,
            suites=args.suites,
            workers=args.workers,
            limit=args.limit,
        )
        print(f"completed {len(rows)} AgentDojo attack combinations")
    else:
        row = run_agentdojo(
            suite_name=(args.suites or ["workspace"])[0],
            user_task=args.user_task,
            injection_task=args.injection_task,
            model_id=args.model_id,
            output_root=args.output_root,
            defense=args.defense,
        )
        print(row)


if __name__ == "__main__":
    main()
