from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from agentgate.config import AgentGateSettings
from agentgate.evaluation import evaluate_dataset
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
    toolsafe.add_argument("--output")

    subparsers.add_parser("list-tools", help="list the controlled tool environment")
    subparsers.add_parser("doctor", help="validate local configuration")

    args = parser.parse_args()
    if args.command == "evaluate":
        asyncio.run(_evaluate(args))
    elif args.command == "evaluate-toolsafe":
        asyncio.run(_evaluate_toolsafe(args))
    elif args.command == "list-tools":
        registry, _ = build_default_registry()
        for spec in registry.specs():
            print(f"{spec.name}\t{spec.profile.action.value}\t{spec.profile.resource}")
    elif args.command == "doctor":
        settings = AgentGateSettings.from_env()
        registry, _ = build_default_registry()
        gateway = AgentGate.create(settings, registry)
        asyncio.run(gateway.initialize())
        print(
            json.dumps(
                {
                    "status": "ok",
                    "tools": len(registry),
                    "llm_enabled": settings.llm_enabled,
                    "llm_key_configured": settings.llm_api_key is not None,
                    "llm_provider": settings.llm_provider,
                    "llm_base_url": settings.llm_base_url,
                    "policy_backend": settings.policy_backend,
                },
                indent=2,
            )
        )


async def _evaluate(args: argparse.Namespace) -> None:
    report = await evaluate_dataset(args.dataset, mode=args.mode, split=args.split)
    rendered = report.model_dump_json(indent=2)
    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


async def _evaluate_toolsafe(args: argparse.Namespace) -> None:
    report = await evaluate_toolsafe(args.source, limit=args.limit)
    rendered = report.model_dump_json(indent=2)
    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()
