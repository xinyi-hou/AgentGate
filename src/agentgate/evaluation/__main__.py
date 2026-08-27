from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from agentgate.evaluation.injecagent import evaluate_injecagent
from agentgate.evaluation.toolsafe import evaluate_toolsafe
from agentgate.evaluation.trajectory import evaluate_trajectory


def main() -> None:
    parser = argparse.ArgumentParser(description="Run reproducible AgentGate evaluations")
    parser.add_argument("benchmark", choices=("injecagent", "toolsafe", "trajectory"))
    parser.add_argument("source", type=Path, nargs="?")
    parser.add_argument("--mode", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.benchmark == "injecagent":
        if args.source is None:
            parser.error("injecagent requires a source checkout")
        report = evaluate_injecagent(args.source, args.mode)
    elif args.benchmark == "toolsafe":
        if args.source is None:
            parser.error("toolsafe requires a source checkout")
        report = asyncio.run(evaluate_toolsafe(args.source, args.mode))
    else:
        report = asyncio.run(evaluate_trajectory(args.mode))
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
