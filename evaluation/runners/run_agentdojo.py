from __future__ import annotations

import argparse
import os
from pathlib import Path

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, get_llm, load_system_message
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import benchmark_suite_with_injections
from agentdojo.logging import OutputLogger
from agentdojo.task_suite.load_suites import get_suite

from evaluation.adapters.agentdojo_agentgate import AgentGateToolsExecutor
from evaluation.recording import git_revision, read_jsonl, write_jsonl


def run_agentdojo(
    *,
    suite_name: str,
    user_task: str,
    injection_task: str,
    model_id: str,
    output_root: str | Path,
) -> dict:
    output_root = Path(output_root)
    llm = get_llm("openai-compatible", "openai-compatible", model_id, "tool")
    executor = AgentGateToolsExecutor(output_root / "raw" / "agentdojo" / "agentgate-audit")
    pipeline = AgentPipeline(
        [
            SystemMessage(load_system_message(None)),
            InitQuery(),
            llm,
            ToolsExecutionLoop([executor, llm]),
        ]
    )
    pipeline.name = "openai-compatible-agentgate"
    suite = get_suite("v1.2", suite_name)
    attacker = load_attack("tool_knowledge", suite, pipeline)
    logdir = output_root / "raw" / "agentdojo" / "agentgate"
    with OutputLogger(str(logdir)):
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
    case_records = [
        item
        for item in executor.records
        if item["user_task_id"] == user_task and item["injection_task_id"] == injection_task
    ]
    row = {
        "benchmark": "AgentDojo",
        "benchmark_commit": git_revision("benchmarks/e2e/agentdojo"),
        "benchmark_version": "0.1.35/v1.2",
        "suite": suite_name,
        "user_task": user_task,
        "injection_task": injection_task,
        "attack": "tool_knowledge",
        "defense": "AgentGate",
        "agent_model": model_id,
        "utility": results["utility_results"][(user_task, injection_task)],
        "attack_success": results["security_results"][(user_task, injection_task)],
        "injection_task_solvable": results["injection_tasks_utility_results"][injection_task],
        "tool_calls": len(case_records),
        "blocked_calls": sum(not item["executed"] for item in case_records),
    }
    normalized_path = output_root / "normalized" / "agentdojo_agentgate.jsonl"
    existing = read_jsonl(normalized_path) if normalized_path.exists() else []
    existing = [
        item
        for item in existing
        if (item["suite"], item["user_task"], item["injection_task"])
        != (suite_name, user_task, injection_task)
    ]
    write_jsonl(normalized_path, [*existing, row])
    write_jsonl(
        output_root
        / "raw"
        / "agentdojo"
        / f"agentgate_calls_{suite_name}_{user_task}_{injection_task}.jsonl",
        executor.records,
    )
    return row


def main() -> None:
    parser = argparse.ArgumentParser(description="Run AgentDojo through AgentGate's tool boundary")
    parser.add_argument("--suite", default="workspace")
    parser.add_argument("--user-task", default="user_task_0")
    parser.add_argument("--injection-task", default="injection_task_0")
    parser.add_argument("--model-id", default=os.getenv("LLM_MODEL_3", "DeepSeek-V4-Pro-0813"))
    parser.add_argument("--output-root", default="evaluation/results")
    args = parser.parse_args()
    row = run_agentdojo(
        suite_name=args.suite,
        user_task=args.user_task,
        injection_task=args.injection_task,
        model_id=args.model_id,
        output_root=args.output_root,
    )
    print(row)


if __name__ == "__main__":
    main()
