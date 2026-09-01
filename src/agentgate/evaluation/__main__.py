from __future__ import annotations

import argparse
import asyncio
import json
import sys
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
    parser.add_argument(
        "--stability",
        action="store_true",
        help="evaluate every configured model instead of only the default semantic model",
    )
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    parser.add_argument("--max-attempts", type=int, default=3)
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
        if min(args.repeats, args.concurrency, args.max_attempts) < 1 or args.timeout_seconds <= 0:
            parser.error(
                "llm --repeats, --concurrency, --timeout-seconds, and --max-attempts "
                "must be positive"
            )
        if args.source is None:
            parser.error("llm requires an explicit capability gold YAML source")
        report = asyncio.run(
            evaluate_llm_capabilities(
                args.source,
                model_names=args.models,
                repeats=args.repeats,
                concurrency=args.concurrency,
                stability=args.stability,
                timeout_seconds=args.timeout_seconds,
                max_attempts=args.max_attempts,
                progress=lambda message: print(f"[llm-eval] {message}", file=sys.stderr),
            )
        )
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
