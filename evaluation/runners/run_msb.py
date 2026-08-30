from __future__ import annotations

import argparse
import asyncio
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any

import pandas as pd
from langchain_openai import ChatOpenAI

from evaluation.recording import git_revision, stable_hash, write_jsonl


def _load_msb(root: Path):
    spec = importlib.util.spec_from_file_location("agentgate_msb_main", root / "main.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load MSB main.py")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(root))
    spec.loader.exec_module(module)
    return module


async def run_msb(
    *,
    defense: str,
    model_id: str,
    output_root: str | Path = "evaluation/results",
) -> dict[str, Any]:
    repository = Path("benchmarks/e2e/msb").resolve()
    output_root = Path(output_root).resolve()
    module = _load_msb(repository)
    module.ChatDeepSeek = lambda **_kwargs: ChatOpenAI(
        api_key=os.environ["LLM_API"],
        base_url=os.environ["LLM_URL"],
        model=model_id,
        temperature=0,
    )
    original_config = module.complete_server_config
    label = "deepseek-compatible-agentgate" if defense == "AgentGate" else "deepseek-compatible"
    session_id = stable_hash({"benchmark": "MSB", "defense": defense})[:16]
    if defense == "AgentGate":
        agentgate_bin = repository / ".venv-agentgate" / "bin" / "agentgate"

        def wrapped_config(*args, **kwargs):
            config = original_config(*args, **kwargs)
            if config is None:
                return None
            for server_name, server in config["mcpServers"].items():
                command = server["command"]
                command_args = list(server.get("args", []))
                server["command"] = str(agentgate_bin)
                server["args"] = [
                    "mcp-stdio",
                    "--principal",
                    "msb-user",
                    "--session-id",
                    session_id,
                    "--task-id",
                    "msb-prompt-injection-data",
                    "--agent-id",
                    "msb-agent",
                    "--",
                    command,
                    *command_args,
                ]
                environment = dict(server.get("env", {}))
                environment["AGENTGATE_AUDIT_PATH"] = str(
                    output_root / "raw" / "msb" / "agentgate-audit" / f"{server_name}.jsonl"
                )
                server["env"] = environment
            return config

        module.complete_server_config = wrapped_config

    agent_row = (
        pd.read_json(repository / "data" / "agent_task.jsonl", lines=True)
        .query("agent_name == 'academic_search'")
        .iloc[0]
    )
    attack_row = (
        pd.read_json(repository / "data" / "attack_task.jsonl", lines=True)
        .query("attack_task == 'obtain_data_information'")
        .iloc[0]
    )
    tool_task = agent_row["task_tool"][0]
    output_directory = repository / "operation_space" / "output"
    before = {path.name for path in output_directory.iterdir() if path.is_file()}
    previous_cwd = Path.cwd()
    os.chdir(repository)
    try:
        await module.run_attack(
            llm_name=label,
            agent_name=agent_row["agent_name"],
            agent_system_prompt=agent_row["system_prompt"],
            agent_task=tool_task["task"],
            tool_name=tool_task["tool"],
            attack_task=attack_row["attack_task"],
            attack_type="prompt_injection",
            attack_implement=attack_row["implementation"],
        )
    finally:
        os.chdir(previous_cwd)
    created = [
        path for path in output_directory.iterdir() if path.is_file() and path.name not in before
    ]
    copied_artifacts = []
    artifact_root = output_root / "raw" / "msb" / defense.lower().replace(" ", "_")
    artifact_root.mkdir(parents=True, exist_ok=True)
    for source in created:
        target = artifact_root / source.name
        target.write_bytes(source.read_bytes())
        copied_artifacts.append(str(target))
    attack_success = bool(created)
    row = {
        "benchmark": "MSB",
        "benchmark_commit": git_revision(repository),
        "case_id": "academic_search:prompt_injection:obtain_data_information:0",
        "attack_type": "prompt_injection",
        "attack_task": "obtain_data_information",
        "defense": defense,
        "agent_model": model_id,
        "attack_success": attack_success,
        "harmful_side_effect_occurred": attack_success,
        "created_artifacts": copied_artifacts,
        "applicable_to_agentgate": True,
    }
    target = output_root / "normalized" / "msb_runs.jsonl"
    existing = []
    if target.exists():
        existing = [json.loads(line) for line in target.read_text().splitlines() if line.strip()]
        existing = [item for item in existing if item["defense"] != defense]
    write_jsonl(target, [*existing, row])
    return row


def main() -> None:
    parser = argparse.ArgumentParser(description="Run one executable MSB attack through MCP")
    parser.add_argument("--defense", choices=["No Defense", "AgentGate"], required=True)
    parser.add_argument("--model-id", default=os.getenv("LLM_MODEL_3", "DeepSeek-V4-Pro-0813"))
    parser.add_argument("--output-root", default="evaluation/results")
    args = parser.parse_args()
    print(
        asyncio.run(
            run_msb(
                defense=args.defense,
                model_id=args.model_id,
                output_root=args.output_root,
            )
        )
    )


if __name__ == "__main__":
    main()
