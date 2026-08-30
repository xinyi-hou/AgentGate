from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from agentgate.evaluation.atg import evaluate_atg, evaluate_atg_overhead
from agentgate.evaluation.injecagent import evaluate_injecagent
from agentgate.evaluation.llm import evaluate_llm_capabilities
from agentgate.evaluation.toolsafe import evaluate_toolsafe
from agentgate.evaluation.trajectory import evaluate_trajectory


def main() -> None:
    parser = argparse.ArgumentParser(description="Run reproducible AgentGate evaluations")
    parser.add_argument(
        "benchmark",
        choices=("injecagent", "toolsafe", "trajectory", "atg", "overhead", "llm"),
    )
    parser.add_argument("source", type=Path, nargs="?")
    parser.add_argument("--mode")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--models", nargs="*")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--concurrency", type=int, default=4)
    args = parser.parse_args()
    if args.benchmark == "injecagent":
        if args.source is None:
            parser.error("injecagent requires a source checkout")
        if args.mode is None:
            parser.error("injecagent requires --mode")
        report = evaluate_injecagent(args.source, args.mode)
    elif args.benchmark == "toolsafe":
        if args.source is None:
            parser.error("toolsafe requires a source checkout")
        if args.mode is None:
            parser.error("toolsafe requires --mode")
        report = asyncio.run(evaluate_toolsafe(args.source, args.mode))
    elif args.benchmark == "trajectory":
        if args.mode is None:
            parser.error("trajectory requires --mode")
        report = asyncio.run(evaluate_trajectory(args.mode))
    elif args.benchmark == "atg":
        if args.mode is None:
            parser.error("atg requires --mode")
        if args.mode not in {
            "full",
            "stateless",
            "no_provenance",
            "same_agent",
            "no_aggregate",
        }:
            parser.error("unsupported atg --mode")
        report = asyncio.run(evaluate_atg(args.mode))
    elif args.benchmark == "overhead":
        report = asyncio.run(evaluate_atg_overhead())
    else:
        if args.repeats < 1 or args.concurrency < 1:
            parser.error("llm --repeats and --concurrency must be positive")
        source = args.source or Path("evaluation/llm_capability_gold.yaml")
        report = asyncio.run(
            evaluate_llm_capabilities(
                source,
                model_names=args.models,
                repeats=args.repeats,
                concurrency=args.concurrency,
            )
        )
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
