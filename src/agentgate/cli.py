from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

from agentgate.config import AgentGateSettings
from agentgate.evaluation import evaluate_dataset
from agentgate.evaluation.adapters.injecagent import evaluate_injecagent
from agentgate.evaluation.adapters.mcp_safetybench import evaluate_mcp_safetybench
from agentgate.evaluation.adapters.tau2 import evaluate_tau2
from agentgate.evaluation.adapters.toolsafe import evaluate_toolsafe
from agentgate.runtime.gateway import AgentGate
from agentgate.tools import build_default_registry


def main() -> None:
    parser = argparse.ArgumentParser(prog="agentgate")
    subparsers = parser.add_subparsers(dest="command", required=True)

    evaluate = subparsers.add_parser("evaluate", help="run a benchmark dataset")
    evaluate.add_argument("--dataset", required=True)
    evaluate.add_argument("--mode", choices=["full", "static", "no_guard"], default="full")
    evaluate.add_argument("--split", choices=["train", "dev", "test"])
    evaluate.add_argument("--output")

    toolsafe = subparsers.add_parser("evaluate-toolsafe", help="evaluate downloaded TS-Bench")
    toolsafe.add_argument("--source", required=True)
    toolsafe.add_argument("--limit", type=int)
    toolsafe.add_argument("--sample-size", type=int)
    toolsafe.add_argument("--sample-seed", type=int, default=20260728)
    toolsafe.add_argument("--mode", choices=["full", "rules", "no_guard"], default="full")
    toolsafe.add_argument("--model", help="configured LLM_MODEL_* alias or its model ID")
    toolsafe.add_argument(
        "--semantic-cache",
        help="reuse call-level semantic facts from a previous compatible ToolSafe report",
    )
    toolsafe.add_argument("--output")

    injecagent = subparsers.add_parser(
        "evaluate-injecagent",
        help="evaluate an InjecAgent checkout without executing attacker tools",
    )
    _add_external_evaluation_arguments(injecagent)
    injecagent.add_argument("--setting", choices=["base", "enhanced", "both"], default="base")

    mcp_safetybench = subparsers.add_parser(
        "evaluate-mcp-safetybench",
        help="evaluate MCP tool poisoning against paired clean descriptions",
    )
    _add_external_evaluation_arguments(mcp_safetybench)

    tau2 = subparsers.add_parser(
        "evaluate-tau2",
        help="replay successful published tau2 tool-call trajectories",
    )
    _add_external_evaluation_arguments(tau2)

    subparsers.add_parser("list-tools", help="list the controlled tool environment")
    subparsers.add_parser("doctor", help="validate local configuration")

    args = parser.parse_args()
    if args.command == "evaluate":
        asyncio.run(_evaluate(args))
    elif args.command == "evaluate-toolsafe":
        asyncio.run(_evaluate_toolsafe(args))
    elif args.command == "evaluate-injecagent":
        asyncio.run(_evaluate_injecagent(args))
    elif args.command == "evaluate-mcp-safetybench":
        asyncio.run(_evaluate_mcp_safetybench(args))
    elif args.command == "evaluate-tau2":
        asyncio.run(_evaluate_tau2(args))
    elif args.command == "list-tools":
        registry, _ = build_default_registry()
        for spec in registry.specs():
            print(f"{spec.name}\t{spec.profile.action.value}\t{spec.profile.resource}")
    elif args.command == "doctor":
        settings = AgentGateSettings.from_env()
        registry, _ = build_default_registry()
        gateway = AgentGate.create(settings, registry)
        asyncio.run(_doctor(gateway))


async def _evaluate(args: argparse.Namespace) -> None:
    report = await evaluate_dataset(args.dataset, mode=args.mode, split=args.split)
    rendered = report.model_dump_json(indent=2)
    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


async def _evaluate_toolsafe(args: argparse.Namespace) -> None:
    report = await evaluate_toolsafe(
        args.source,
        settings=_external_settings(args),
        mode=args.mode,
        limit=args.limit,
        sample_size=args.sample_size,
        sample_seed=args.sample_seed,
        semantic_cache=args.semantic_cache,
    )
    rendered = report.model_dump_json(indent=2)
    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


async def _evaluate_injecagent(args: argparse.Namespace) -> None:
    report = await evaluate_injecagent(
        args.source,
        settings=_external_settings(args),
        mode=args.mode,
        setting=args.setting,
        limit=args.limit,
    )
    _render_report(report, args.output)


async def _evaluate_mcp_safetybench(args: argparse.Namespace) -> None:
    report = await evaluate_mcp_safetybench(
        args.source,
        settings=_external_settings(args),
        mode=args.mode,
        limit=args.limit,
    )
    _render_report(report, args.output)


async def _evaluate_tau2(args: argparse.Namespace) -> None:
    report = await evaluate_tau2(
        args.source,
        settings=_external_settings(args),
        mode=args.mode,
        limit=args.limit,
    )
    _render_report(report, args.output)


def _add_external_evaluation_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--source", required=True)
    parser.add_argument("--mode", choices=["full", "rules", "no_guard"], default="full")
    parser.add_argument("--model", help="configured LLM_MODEL_* alias or its model ID")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--output")


def _external_settings(args: argparse.Namespace) -> AgentGateSettings:
    if args.model:
        return AgentGateSettings.for_model(args.model)
    return AgentGateSettings.from_env()


def _render_report(report: Any, output: str | None) -> None:
    rendered = report.model_dump_json(indent=2)
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


async def _doctor(gateway: AgentGate) -> None:
    try:
        await gateway.initialize()
        settings = gateway.settings
        print(
            json.dumps(
                {
                    "status": "ok",
                    "tools": len(gateway.registry),
                    "llm_enabled": settings.llm_enabled,
                    "llm_key_configured": settings.llm_api_key is not None,
                    "llm_provider": settings.llm_provider,
                    "llm_base_url": settings.llm_base_url,
                    "policy_backend": settings.policy_backend,
                },
                indent=2,
            )
        )
    finally:
        await gateway.aclose()


if __name__ == "__main__":
    main()
