from __future__ import annotations

import ast
import json
import time
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from agentgate.config import AgentGateSettings
from agentgate.evaluation.metrics import MetricRow, compute_metrics
from agentgate.llm import LLMAnalyzer
from agentgate.models import ToolSpec
from agentgate.modules.integrity import IntegrityModule
from agentgate.modules.integrity.detector import BoundaryAnalysisInput, InstructionBoundaryDetector
from agentgate.modules.integrity.profiler import ToolProfiler


class MCPSafetyBenchReport(BaseModel):
    source: str
    mode: str
    metrics: dict[str, float | int]
    by_domain: dict[str, dict[str, float | int]] = Field(default_factory=dict)
    by_attack_category: dict[str, dict[str, float | int]] = Field(default_factory=dict)
    analysis: dict[str, Any] = Field(default_factory=dict)
    rows: list[dict[str, Any]] = Field(default_factory=list)


_DOMAIN_SERVERS = {
    "browser_automation": "playwright",
    "financial_analysis": "yahoo_finance",
    "location_navigation": "google_maps",
    "repository_management": "github",
    "web_search": "google_search",
}


async def evaluate_mcp_safetybench(
    source: str | Path,
    *,
    settings: AgentGateSettings | None = None,
    mode: Literal["full", "rules", "no_guard"] = "full",
    limit: int | None = None,
) -> MCPSafetyBenchReport:
    root = Path(source)
    task_root = root / "mcpuniverse/benchmark/configs/test"
    server_root = root / "mcpuniverse/mcp/servers"
    if not task_root.is_dir() or not server_root.is_dir():
        raise FileNotFoundError(f"invalid MCP-SafetyBench checkout: {root}")

    task_paths = sorted(task_root.glob("*/*.json"))
    if limit is not None:
        task_paths = task_paths[:limit]
    base_settings = settings or AgentGateSettings.from_env()
    effective = (
        base_settings.model_copy(update={"llm_enabled": False})
        if mode == "rules"
        else base_settings
    )
    llm = LLMAnalyzer(effective)
    integrity = IntegrityModule(
        ToolProfiler(),
        InstructionBoundaryDetector(llm),
        blocking_threshold=effective.integrity_block_severity,
    )
    definitions = _load_server_definitions(server_root)
    metric_rows: list[MetricRow] = []
    details: list[dict[str, Any]] = []
    started_all = time.perf_counter()
    entries: list[dict[str, Any]] = []
    for path in task_paths:
        task = json.loads(path.read_text(encoding="utf-8"))
        domain = path.parent.name
        attack_category = str(task.get("attack_category", "unknown"))
        modifications = task.get("mcp_server_modifications", [])
        for modification_index, modification in enumerate(modifications):
            tool_name = str(modification["tool_name"])
            clean_description, input_schema = _definition_for(
                definitions,
                _DOMAIN_SERVERS[domain],
                tool_name,
            )
            clean_content, poisoned_content, content_kind = _modification_contents(
                modification,
                clean_description,
            )
            pair_id = f"{domain}:{path.stem}:{modification_index}"
            for variant, content, malicious in (
                ("clean", clean_content, False),
                ("poisoned", poisoned_content, True),
            ):
                item_id = f"{pair_id}:{variant}"
                entries.append(
                    {
                        "item_id": item_id,
                        "pair_id": pair_id,
                        "path": path,
                        "domain": domain,
                        "attack_category": attack_category,
                        "tool_name": tool_name,
                        "variant": variant,
                        "malicious": malicious,
                        "content": content,
                        "content_kind": content_kind,
                        "spec": ToolSpec(
                            name=tool_name,
                            description=(
                                content if content_kind == "tool_description" else clean_description
                            ),
                            input_schema=input_schema,
                            namespace=f"mcp-safetybench:{pair_id}:{variant}",
                            source="mcp-safetybench",
                            publisher="MCP-SafetyBench",
                            trusted=False,
                        ),
                    }
                )

    known_tools = {tool_name for _, tool_name in definitions}
    semantic_started = time.perf_counter()
    precomputed = (
        await integrity.detector.analyze_many(
            [
                BoundaryAnalysisInput(
                    item_id=str(entry["item_id"]),
                    content=str(entry["content"]),
                    known_tools=known_tools,
                    content_kind=str(entry["content_kind"]),
                    current_tool=str(entry["tool_name"]),
                )
                for entry in entries
            ],
            use_llm=mode == "full",
            batch_size=effective.llm_batch_size,
            concurrency=effective.llm_concurrency,
        )
        if mode != "no_guard" and effective.integrity_enabled
        else {}
    )
    semantic_wall_time = time.perf_counter() - semantic_started

    for entry in entries:
        spec: ToolSpec = entry["spec"]
        row_started = time.perf_counter()
        if mode == "no_guard" or not effective.integrity_enabled:
            blocked = False
            findings: list[dict[str, Any]] = []
        else:
            entry_findings = precomputed[str(entry["item_id"])]
            if entry["content_kind"] == "tool_description":
                result = await integrity.register(
                    spec,
                    precomputed_findings=entry_findings,
                )
                blocked = result.blocked
                findings = [item.model_dump(mode="json") for item in result.findings]
            else:
                blocked = any(
                    finding.severity >= effective.integrity_block_severity
                    for finding in entry_findings
                )
                findings = [item.model_dump(mode="json") for item in entry_findings]
        predicted = "DENY" if blocked else "ALLOW"
        expected = "DENY" if entry["malicious"] else "ALLOW"
        latency_ms = (time.perf_counter() - row_started) * 1000
        metric_rows.append(
            MetricRow(
                case_id=str(entry["pair_id"]),
                category=str(entry["domain"]),
                malicious=bool(entry["malicious"]),
                expected=expected,
                predicted=predicted,
                latency_ms=latency_ms,
            )
        )
        details.append(
            {
                "case_id": entry["pair_id"],
                "task_file": str(entry["path"].relative_to(root)),
                "domain": entry["domain"],
                "attack_category": entry["attack_category"],
                "tool": entry["tool_name"],
                "content_kind": entry["content_kind"],
                "content_excerpt": str(entry["content"])[:600],
                "variant": entry["variant"],
                "expected": expected,
                "predicted": predicted,
                "latency_ms": latency_ms,
                "findings": findings,
            }
        )

    report = MCPSafetyBenchReport(
        source=str(root),
        mode=mode,
        metrics=compute_metrics(metric_rows),
        by_domain={
            domain: compute_metrics([row for row in metric_rows if row.category == domain])
            for domain in sorted({row.category for row in metric_rows})
        },
        by_attack_category={
            category: compute_metrics(
                [
                    row
                    for row, detail in zip(metric_rows, details, strict=True)
                    if detail["attack_category"] == category
                ]
            )
            for category in sorted({str(row["attack_category"]) for row in details})
        },
        analysis={
            "tasks": len(task_paths),
            "modifications": sum(
                len(
                    json.loads(path.read_text(encoding="utf-8")).get(
                        "mcp_server_modifications", []
                    )
                )
                for path in task_paths
            ),
            "description_modifications": sum(
                "modification_description" in modification
                for path in task_paths
                for modification in json.loads(path.read_text(encoding="utf-8")).get(
                    "mcp_server_modifications", []
                )
            ),
            "return_modifications": sum(
                "modification_return" in modification
                for path in task_paths
                for modification in json.loads(path.read_text(encoding="utf-8")).get(
                    "mcp_server_modifications", []
                )
            ),
            "paired_clean_controls": True,
            "cold_start_namespaces": True,
            "integrity_enabled": effective.integrity_enabled,
            "semantic_wall_time_seconds": semantic_wall_time,
            "wall_time_seconds": time.perf_counter() - started_all,
            "llm_available": llm.available,
            "llm_model": effective.llm_model if llm.available else None,
            "llm_client": llm.stats(),
        },
        rows=details,
    )
    await llm.aclose()
    return report


def _modification_contents(
    modification: dict[str, Any],
    clean_description: str,
) -> tuple[str, str, str]:
    if "modification_description" in modification:
        return clean_description, str(modification["modification_description"]), "tool_description"
    if "modification_return" in modification:
        poisoned = modification["modification_return"]
        clean = _neutral_return(poisoned)
        return (
            json.dumps(clean, ensure_ascii=False, sort_keys=True),
            json.dumps(poisoned, ensure_ascii=False, sort_keys=True),
            "tool_result",
        )
    raise ValueError(f"unsupported MCP modification fields: {sorted(modification)}")


def _neutral_return(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _neutral_return(nested) for key, nested in value.items()}
    if isinstance(value, list):
        return [_neutral_return(nested) for nested in value]
    if isinstance(value, str):
        return "Tool operation completed successfully."
    return value


def _load_server_definitions(
    server_root: Path,
) -> dict[tuple[str, str], tuple[str, dict[str, Any]]]:
    definitions: dict[tuple[str, str], tuple[str, dict[str, Any]]] = {}
    for path in sorted(server_root.glob("*/server.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            docstring = ast.get_docstring(node)
            if not docstring:
                continue
            properties: dict[str, dict[str, str]] = {}
            for argument in node.args.args:
                if argument.arg in {"self", "cls"}:
                    continue
                properties[argument.arg] = {"type": _json_type(argument.annotation)}
            definitions[(path.parent.name, node.name)] = (
                docstring.strip(),
                {"type": "object", "properties": properties},
            )
    return definitions


def _definition_for(
    definitions: dict[tuple[str, str], tuple[str, dict[str, Any]]],
    server: str,
    tool_name: str,
) -> tuple[str, dict[str, Any]]:
    try:
        return definitions[(server, tool_name)]
    except KeyError as exc:
        raise ValueError(f"missing original MCP definition for {server}.{tool_name}") from exc


def _json_type(annotation: ast.expr | None) -> str:
    if isinstance(annotation, ast.Name):
        return {
            "str": "string",
            "int": "integer",
            "float": "number",
            "bool": "boolean",
            "dict": "object",
            "list": "array",
        }.get(annotation.id, "string")
    if isinstance(annotation, ast.Subscript) and isinstance(annotation.value, ast.Name):
        return {"List": "array", "Dict": "object", "Optional": "string"}.get(
            annotation.value.id,
            "string",
        )
    return "string"
