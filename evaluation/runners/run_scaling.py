from __future__ import annotations

import argparse
import asyncio
import statistics
import tempfile
import time
from pathlib import Path
from typing import Any

from agentgate.adapters import FunctionToolAdapter
from agentgate.runtime import RuntimeContext
from evaluation.recording import write_csv, write_jsonl
from evaluation.statefulbench.runner import (
    _build_runtime,
    _graph_snapshot,
    _register_tools,
    _rss_bytes,
)
from evaluation.statefulbench.tools import StatefulEnvironment

CALL_COUNTS = (5, 10, 20, 40, 80)
MODES = ("no_defense", "event_only", "full")
MODE_LABELS = {
    "no_defense": "No Defense (direct executor)",
    "event_only": "AgentGate Rules-only",
    "full": "AgentGate Full",
}


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = (len(ordered) - 1) * percentile
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = rank - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


async def _direct_workload(environment: StatefulEnvironment, calls: int) -> dict[str, Any]:
    latencies: list[float] = []
    value: Any = ""
    for index in range(calls):
        started = time.perf_counter()
        if index == 0:
            result = await environment.sensitive_read({"customer_id": "scaling-customer"})
            value = result.output["email"]
        else:
            result = await environment.transform({"value": value, "mode": "hash"})
            value = result["value"]
        latencies.append((time.perf_counter() - started) * 1000)
    return {"latencies": latencies, "graph": None}


async def _agentgate_workload(
    environment: StatefulEnvironment,
    calls: int,
    mode: str,
    audit_path: Path,
) -> dict[str, Any]:
    runtime = _build_runtime(mode, environment, audit_path)
    adapter = FunctionToolAdapter(runtime)
    await _register_tools(adapter, environment)
    context = RuntimeContext(
        principal="scaling-user",
        session_id=f"scaling-{mode}-{calls}",
        task_id=f"scaling-{calls}",
        agent_id="scaling-agent",
    )
    latencies: list[float] = []
    value: Any = ""
    for index in range(calls):
        tool_name = "server_a.customer.read" if index == 0 else "server_a.data.transform"
        arguments = (
            {"customer_id": "scaling-customer"} if index == 0 else {"value": value, "mode": "hash"}
        )
        started = time.perf_counter()
        outcome = await adapter.invoke(
            tool_name=tool_name,
            arguments=arguments,
            context=context,
            call_id=f"scaling-{mode}-{calls}-{index}",
            source_framework="statefulbench-scaling",
            source_transport="in_process_executable",
        )
        latencies.append((time.perf_counter() - started) * 1000)
        if outcome.execution is None or not outcome.execution.success:
            raise RuntimeError(f"scaling call was not executed: {outcome.decision}")
        output = outcome.execution.output
        value = output["email"] if index == 0 else output["value"]
    graph = await runtime.graph_store.get_session_graph(context.principal, context.session_id)
    await runtime.aclose()
    return {"latencies": latencies, "graph": _graph_snapshot(graph)}


async def run_scaling(output_root: str | Path = "evaluation/results") -> list[dict[str, Any]]:
    output_root = Path(output_root)
    rows: list[dict[str, Any]] = []
    for calls in CALL_COUNTS:
        for mode in MODES:
            with tempfile.TemporaryDirectory(prefix="agentgate-scaling-") as temp:
                environment = StatefulEnvironment(Path(temp))
                rss_before = _rss_bytes()
                task_started = time.perf_counter()
                if mode == "no_defense":
                    result = await _direct_workload(environment, calls)
                else:
                    result = await _agentgate_workload(
                        environment,
                        calls,
                        mode,
                        output_root / "raw" / "scaling-audit" / f"{mode}-{calls}.jsonl",
                    )
                task_ms = (time.perf_counter() - task_started) * 1000
                latencies = result["latencies"]
                graph = result["graph"]
                rows.append(
                    {
                        "mode": MODE_LABELS[mode],
                        "tool_calls": calls,
                        "task_latency_ms": task_ms,
                        "calls_per_second": calls / (task_ms / 1000),
                        "p50_call_latency_ms": _percentile(latencies, 0.50),
                        "p95_call_latency_ms": _percentile(latencies, 0.95),
                        "p99_call_latency_ms": _percentile(latencies, 0.99),
                        "mean_call_latency_ms": statistics.mean(latencies),
                        "process_rss_delta_bytes": max(0, _rss_bytes() - rss_before),
                        "agent_nodes": graph.agent_nodes if graph else 0,
                        "tool_event_nodes": graph.tool_event_nodes if graph else 0,
                        "data_object_nodes": graph.data_object_nodes if graph else 0,
                        "total_edges": graph.edges if graph else 0,
                        "provenance_edges": graph.provenance_edges if graph else 0,
                        "max_provenance_depth": graph.max_provenance_depth if graph else 0,
                        "propagated_label_count": graph.propagated_label_count if graph else 0,
                        "graph_memory_bytes": graph.graph_memory_bytes if graph else 0,
                    }
                )
    write_jsonl(output_root / "raw" / "scaling_runs.jsonl", rows)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Run executable AgentGate ATG scaling workload")
    parser.add_argument("--output-root", default="evaluation/results")
    args = parser.parse_args()
    rows = asyncio.run(run_scaling(args.output_root))
    runtime_fields = [
        "mode",
        "tool_calls",
        "task_latency_ms",
        "calls_per_second",
        "p50_call_latency_ms",
        "p95_call_latency_ms",
        "p99_call_latency_ms",
        "mean_call_latency_ms",
        "process_rss_delta_bytes",
    ]
    graph_fields = [
        "mode",
        "tool_calls",
        "agent_nodes",
        "tool_event_nodes",
        "data_object_nodes",
        "total_edges",
        "provenance_edges",
        "max_provenance_depth",
        "propagated_label_count",
        "graph_memory_bytes",
        "mean_call_latency_ms",
    ]
    write_csv(Path(args.output_root) / "tables" / "rq4_runtime_overhead.csv", rows, runtime_fields)
    write_csv(Path(args.output_root) / "tables" / "rq4_graph_scaling.csv", rows, graph_fields)


if __name__ == "__main__":
    main()
