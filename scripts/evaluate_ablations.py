from __future__ import annotations

import argparse
import asyncio
import json
import re
import time
from pathlib import Path
from typing import Any

from agentgate.config import AgentGateSettings
from agentgate.evaluation import evaluate_dataset
from agentgate.evaluation.adapters.toolsafe import evaluate_toolsafe

ABLATIONS: tuple[tuple[str, dict[str, bool]], ...] = (
    ("full", {}),
    ("without_integrity", {"integrity_enabled": False}),
    ("without_authorization", {"authorization_enabled": False}),
    ("without_trajectory", {"trajectory_enabled": False}),
    ("without_provenance_fusion", {"provenance_fusion_enabled": False}),
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run paired AgentGate module ablations on one fixed benchmark."
    )
    parser.add_argument("--benchmark", choices=["agentgatebench", "toolsafe"], required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--mode", choices=["full", "rules"], default="rules")
    parser.add_argument("--model", help="configured LLM_MODEL_* alias or model ID")
    parser.add_argument("--sample-size", type=int)
    parser.add_argument("--sample-seed", type=int, default=20260728)
    parser.add_argument("--output-dir", required=True)
    return parser


async def _run(args: argparse.Namespace) -> dict[str, Any]:
    base = AgentGateSettings.for_model(args.model) if args.model else AgentGateSettings.from_env()
    if args.mode == "rules":
        base = base.model_copy(update={"llm_enabled": False})

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    reports: dict[str, Any] = {}
    summaries: list[dict[str, Any]] = []
    for name, update in ABLATIONS:
        started = time.perf_counter()
        settings = base.model_copy(update=update)
        if args.benchmark == "toolsafe":
            report = await evaluate_toolsafe(
                args.source,
                settings=settings,
                mode=args.mode,
                sample_size=args.sample_size,
                sample_seed=args.sample_seed,
            )
        else:
            report = await evaluate_dataset(
                args.source,
                mode="full",
                settings=settings,
            )
        wall_time_seconds = time.perf_counter() - started
        reports[name] = report
        report_path = output_dir / f"{_slug(name)}.json"
        report_path.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
        summaries.append(
            {
                "ablation": name,
                **{
                    key: report.metrics[key]
                    for key in (
                        "cases",
                        "accuracy",
                        "f1",
                        "tp",
                        "fp",
                        "tn",
                        "fn",
                        "false_negative_rate",
                        "false_positive_rate",
                        "benign_completion_rate",
                    )
                },
                "wall_time_seconds": wall_time_seconds,
            }
        )

    full = reports["full"]
    paired = {
        name: _paired_change(full.rows, report.rows)
        for name, report in reports.items()
        if name != "full"
    }
    summary = {
        "benchmark": args.benchmark,
        "source": args.source,
        "mode": args.mode,
        "model": base.llm_model if base.llm_enabled else None,
        "sample_size": args.sample_size,
        "sample_seed": args.sample_seed if args.sample_size else None,
        "ablations": summaries,
        "paired_decision_changes": paired,
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return summary


def _paired_change(
    full_rows: list[dict[str, Any]], ablated_rows: list[dict[str, Any]]
) -> dict[str, int]:
    paired = list(zip(full_rows, ablated_rows, strict=True))
    return {
        "common_cases": len(paired),
        "full_only_blocks": sum(
            _blocked(full) and not _blocked(ablated) for full, ablated in paired
        ),
        "ablation_only_blocks": sum(
            not _blocked(full) and _blocked(ablated) for full, ablated in paired
        ),
        "same_decision": sum(
            _blocked(full) == _blocked(ablated) for full, ablated in paired
        ),
    }


def _blocked(row: dict[str, Any]) -> bool:
    return str(row.get("predicted", "ALLOW")) != "ALLOW"


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9_.-]+", "-", value.lower()).strip("-")


def main() -> None:
    args = _parser().parse_args()
    print(json.dumps(asyncio.run(_run(args)), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
