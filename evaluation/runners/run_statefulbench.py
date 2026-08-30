from __future__ import annotations

import argparse
import asyncio

from evaluation.metrics import summarize
from evaluation.recording import write_jsonl
from evaluation.statefulbench.runner import run_statefulbench


def main() -> None:
    parser = argparse.ArgumentParser(description="Run executable AgentGate-StatefulBench")
    parser.add_argument("--output-root", default="evaluation/results")
    parser.add_argument("--mode", action="append", dest="modes")
    args = parser.parse_args()
    if args.modes:
        tasks, _ = asyncio.run(run_statefulbench(modes=args.modes, output_root=args.output_root))
    else:
        tasks, _ = asyncio.run(run_statefulbench(output_root=args.output_root))
    write_jsonl(f"{args.output_root}/normalized/statefulbench_summary.jsonl", summarize(tasks))


if __name__ == "__main__":
    main()
