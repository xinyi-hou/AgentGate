from __future__ import annotations

import argparse
import asyncio
import json
import re
import time
from itertools import combinations
from pathlib import Path
from statistics import mean, pstdev
from typing import Any

from agentgate.config import AgentGateSettings
from agentgate.evaluation.adapters.mcp_safetybench import (
    MCPSafetyBenchReport,
    evaluate_mcp_safetybench,
)
from agentgate.evaluation.adapters.toolsafe import ToolSafeReport, evaluate_toolsafe

EvaluationReport = ToolSafeReport | MCPSafetyBenchReport


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compare AgentGate semantic evidence extraction across LLM families."
    )
    parser.add_argument("--source", required=True)
    parser.add_argument(
        "--benchmark",
        choices=["toolsafe", "mcp-safetybench"],
        default="toolsafe",
    )
    parser.add_argument("--model", action="append", required=True)
    parser.add_argument("--sample-size", type=int, default=600)
    parser.add_argument("--sample-seed", type=int, default=20260728)
    parser.add_argument(
        "--development-sample-size",
        type=int,
        help="assert that the evaluated interactions do not overlap this development sample",
    )
    parser.add_argument("--development-sample-seed", type=int, default=20260728)
    parser.add_argument("--batch-size", type=int, default=10)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--retries", type=int, default=0)
    parser.add_argument(
        "--model-wall-timeout",
        type=float,
        default=900.0,
        help="maximum wall time for one model before recording an unavailable result",
    )
    parser.add_argument("--output-dir", default="artifacts/results/model-matrix")
    return parser


async def _run(args: argparse.Namespace) -> dict[str, Any]:
    base = AgentGateSettings.from_env()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    rules_settings = base.model_copy(update={"llm_enabled": False})
    rules_report = await _evaluate_one(args, rules_settings, mode="rules")
    holdout_validation = (
        await _validate_holdout(args, rules_settings, rules_report)
        if args.benchmark == "toolsafe"
        else None
    )
    (output_dir / "rules-only.json").write_text(
        rules_report.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
    rules_summary = _summary_row("rules-only", rules_report)

    reports: dict[str, EvaluationReport] = {}
    rows: list[dict[str, Any]] = []
    for model in args.model:
        print(f"starting {model}", flush=True)
        model_started = time.perf_counter()
        settings = AgentGateSettings.for_model(model).model_copy(
            update={
                "llm_batch_size": args.batch_size,
                "llm_concurrency": args.concurrency,
                "llm_timeout_seconds": args.timeout,
                "llm_max_retries": args.retries,
            }
        )
        try:
            report = await asyncio.wait_for(
                _evaluate_one(args, settings, mode="full"),
                timeout=args.model_wall_timeout,
            )
        except Exception as exc:
            failure = {
                "model": model,
                "status": "unavailable",
                "error_type": type(exc).__name__,
                "error": str(exc)[:500],
                "wall_time_seconds": time.perf_counter() - model_started,
                "request_metrics": "unavailable because evaluation was cancelled",
            }
            rows.append(failure)
            (output_dir / f"{_slug(model)}-failure.json").write_text(
                json.dumps(failure, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            print(f"failed {model}: {type(exc).__name__}", flush=True)
            continue
        reports[model] = report
        report_path = output_dir / f"{_slug(model)}.json"
        report_path.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
        model_summary = _summary_row(model, report)
        model_summary["status"] = _completion_status(report)
        model_summary["delta_vs_rules"] = _metric_delta(model_summary, rules_summary)
        rows.append(model_summary)
        print(f"completed {model}", flush=True)

    summary = {
        "source": args.source,
        "benchmark": args.benchmark,
        "sample_size_requested": (
            args.sample_size if args.benchmark == "toolsafe" else None
        ),
        "sample_seed": args.sample_seed if args.benchmark == "toolsafe" else None,
        "per_request_timeout_seconds": args.timeout,
        "per_model_wall_timeout_seconds": args.model_wall_timeout,
        "max_retries": args.retries,
        "holdout_validation": holdout_validation,
        "rules_baseline": rules_summary,
        "models": rows,
        "cross_model_stability": _cross_model_stability(reports),
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return summary


async def _validate_holdout(
    args: argparse.Namespace,
    rules_settings: AgentGateSettings,
    evaluated_report: EvaluationReport,
) -> dict[str, Any] | None:
    if args.development_sample_size is None:
        return None
    development_report = await evaluate_toolsafe(
        args.source,
        settings=rules_settings,
        mode="rules",
        sample_size=args.development_sample_size,
        sample_seed=args.development_sample_seed,
    )
    evaluated = _interaction_keys(evaluated_report)
    development = _interaction_keys(development_report)
    overlap = evaluated & development
    if overlap:
        preview = sorted(overlap)[:5]
        raise RuntimeError(
            f"evaluation sample overlaps {len(overlap)} development interactions: {preview}"
        )
    return {
        "development_sample_size_requested": args.development_sample_size,
        "development_sample_seed": args.development_sample_seed,
        "development_records": len(development_report.rows),
        "development_interactions": len(development),
        "evaluated_interactions": len(evaluated),
        "overlap_interactions": 0,
    }


async def _evaluate_one(
    args: argparse.Namespace,
    settings: AgentGateSettings,
    *,
    mode: str,
) -> EvaluationReport:
    if args.benchmark == "mcp-safetybench":
        return await evaluate_mcp_safetybench(
            args.source,
            settings=settings,
            mode=mode,
        )
    return await evaluate_toolsafe(
        args.source,
        settings=settings,
        mode=mode,
        sample_size=args.sample_size,
        sample_seed=args.sample_seed,
    )


def _summary_row(model: str, report: EvaluationReport) -> dict[str, Any]:
    metrics = report.metrics
    trajectory = report.analysis.get("trajectory", {})
    client = report.analysis.get("llm_client", {})
    return {
        "model": model,
        "cases": metrics.get("cases", 0),
        "accuracy": metrics.get("accuracy", 0.0),
        "f1": metrics.get("f1", 0.0),
        "tp": metrics.get("tp", 0),
        "fp": metrics.get("fp", 0),
        "tn": metrics.get("tn", 0),
        "fn": metrics.get("fn", 0),
        "attack_success_rate": metrics.get("attack_success_rate", 0.0),
        "false_negative_rate": metrics.get("false_negative_rate", 0.0),
        "benign_completion_rate": metrics.get("benign_completion_rate", 0.0),
        "false_positive_rate": metrics.get("false_positive_rate", 0.0),
        "reachable_metrics": trajectory.get("reachable_metrics", {}),
        "interaction_attack_success_rate": trajectory.get("attack_success_rate", 0.0),
        "interaction_confusion": trajectory.get("interaction_confusion", {}),
        "requests": client.get("requests", 0),
        "failures": client.get("failures", 0),
        "prompt_tokens": client.get("prompt_tokens", 0),
        "completion_tokens": client.get("completion_tokens", 0),
        "total_tokens": client.get("total_tokens", 0),
        "request_success_rate": (
            (client.get("requests", 0) - client.get("failures", 0))
            / client.get("requests", 1)
            if client.get("requests", 0)
            else 0.0
        ),
        "mean_request_latency_ms": client.get("mean_request_latency_ms", 0.0),
        "request_latency_p95_ms": client.get("request_latency_p95_ms", 0.0),
        "wall_time_seconds": report.analysis.get("wall_time_seconds", 0.0),
        "semantic_wall_time_seconds": report.analysis.get(
            "semantic_wall_time_seconds", 0.0
        ),
        "error_counts": client.get("error_counts", {}),
        "semantic_source_counts": report.analysis.get("semantic_source_counts", {}),
    }


def _completion_status(report: EvaluationReport) -> str:
    client = report.analysis.get("llm_client", {})
    requests = int(client.get("requests", 0))
    failures = int(client.get("failures", 0))
    if requests == 0 or failures >= requests:
        return "unavailable"
    return "degraded" if failures else "completed"


def _cross_model_stability(reports: dict[str, EvaluationReport]) -> dict[str, Any]:
    reports = {
        model: report
        for model, report in reports.items()
        if _completion_status(report) != "unavailable"
    }
    if not reports:
        return {}
    metric_names = (
        "accuracy",
        "f1",
        "attack_success_rate",
        "false_negative_rate",
        "benign_completion_rate",
        "false_positive_rate",
    )
    dispersion: dict[str, dict[str, float]] = {}
    for metric in metric_names:
        values = [float(report.metrics[metric]) for report in reports.values()]
        dispersion[metric] = {
            "mean": mean(values),
            "population_stddev": pstdev(values),
            "range": max(values) - min(values),
        }

    decisions = {
        model: {_row_key(row): row["predicted"] for row in report.rows}
        for model, report in reports.items()
    }
    common = set.intersection(*(set(values) for values in decisions.values()))
    pairwise: dict[str, float] = {}
    for left, right in combinations(reports, 2):
        agreed = sum(decisions[left][key] == decisions[right][key] for key in common)
        pairwise[f"{left}::{right}"] = agreed / len(common) if common else 0.0
    unanimous = sum(
        len({model_decisions[key] for model_decisions in decisions.values()}) == 1 for key in common
    )
    return {
        "metric_dispersion": dispersion,
        "common_cases": len(common),
        "unanimous_decision_rate": unanimous / len(common) if common else 0.0,
        "pairwise_decision_agreement": pairwise,
    }


def _metric_delta(
    model: dict[str, Any],
    baseline: dict[str, Any],
) -> dict[str, float]:
    return {
        metric: float(model[metric]) - float(baseline[metric])
        for metric in (
            "accuracy",
            "f1",
            "attack_success_rate",
            "false_negative_rate",
            "benign_completion_rate",
            "false_positive_rate",
        )
    }


def _row_key(row: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(row.get("source") or row.get("task_file", "")),
        str(row.get("interaction_id") or row.get("case_id", "")),
        str(row.get("segment_id") or row.get("variant", "")),
        str(row.get("action") or row.get("tool", "")),
    )


def _interaction_keys(report: ToolSafeReport) -> set[tuple[str, str]]:
    return {
        (
            str(row.get("source", "")),
            str(row.get("interaction_id") or row.get("segment_id", "")),
        )
        for row in report.rows
    }


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9_.-]+", "-", value.lower()).strip("-")


def main() -> None:
    args = _parser().parse_args()
    print(json.dumps(asyncio.run(_run(args)), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
