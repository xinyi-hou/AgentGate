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
from agentgate.models import (
    Action,
    DecisionAction,
    IntegrityResult,
    ToolCall,
    ToolProfile,
    ToolSpec,
)
from agentgate.modules.authorization import (
    AuthorizationModule,
    CallSemanticRiskDetector,
    TaskContractBuilder,
    TaskSafetyDetector,
)
from agentgate.modules.integrity import IntegrityModule
from agentgate.modules.integrity.detector import (
    BoundaryAnalysisInput,
    InstructionBoundaryDetector,
)
from agentgate.modules.integrity.profiler import ToolProfiler
from agentgate.policy import BuiltinPolicyBackend


class InjecAgentReport(BaseModel):
    source: str
    setting: str
    mode: str
    metrics: dict[str, float | int]
    by_stage: dict[str, dict[str, float | int]] = Field(default_factory=dict)
    by_attack_type: dict[str, dict[str, float | int]] = Field(default_factory=dict)
    analysis: dict[str, Any] = Field(default_factory=dict)
    rows: list[dict[str, Any]] = Field(default_factory=list)


async def evaluate_injecagent(
    source: str | Path,
    *,
    settings: AgentGateSettings | None = None,
    setting: Literal["base", "enhanced", "both"] = "base",
    mode: Literal["full", "rules", "no_guard"] = "full",
    limit: int | None = None,
) -> InjecAgentReport:
    root = Path(source)
    data_root = root / "data"
    if not data_root.is_dir():
        raise FileNotFoundError(f"invalid InjecAgent checkout: {root}")
    started_all = time.perf_counter()
    records = _load_cases(data_root, setting)
    if limit is not None:
        records = records[:limit]
    catalog = _load_tool_catalog(data_root / "tools.json")
    base_settings = settings or AgentGateSettings.from_env()
    effective = (
        base_settings.model_copy(update={"llm_enabled": False})
        if mode == "rules"
        else base_settings
    )
    llm = LLMAnalyzer(effective)
    profiler = ToolProfiler()
    detector = InstructionBoundaryDetector(llm)
    integrity = IntegrityModule(
        profiler,
        detector,
        blocking_threshold=effective.integrity_block_severity,
    )
    authorization = AuthorizationModule(
        BuiltinPolicyBackend(),
        task_safety=TaskSafetyDetector(),
        semantic_risk=CallSemanticRiskDetector(
            None,
            provenance_enabled=effective.provenance_fusion_enabled,
        ),
    )
    contracts = TaskContractBuilder()
    registrations: dict[str, Any] = {}
    for name, spec in catalog.items():
        registrations[name] = (
            await integrity.register(
                spec,
                precomputed_findings=await detector.analyze(
                    spec.description,
                    set(catalog),
                    use_llm=False,
                    content_kind="tool_description",
                    current_tool=spec.name,
                ),
            )
            if effective.integrity_enabled
            else IntegrityResult(
                trust_level="integrity_ablation",
                profile=await profiler.build(spec),
                sanitized_content=spec.description,
            )
        )

    content_items: list[BoundaryAnalysisInput] = []
    for index, record in enumerate(records):
        injected_content = str(record.get("Tool Response", ""))
        clean_content = str(record.get("Tool Response Template", "")).replace(
            "<Attacker Instruction>",
            "External content returned by the requested service.",
        )
        for stage, content in (
            ("clean_result", clean_content),
            ("injected_result", injected_content),
        ):
            item_id = f"{index}:{stage}"
            content_items.append(
                BoundaryAnalysisInput(
                    item_id=item_id,
                    content=content,
                    known_tools=set(catalog),
                    content_kind="tool_result",
                )
            )
    semantic_started = time.perf_counter()
    content_findings_by_id = (
        await detector.analyze_many(
            content_items,
            use_llm=mode == "full",
            batch_size=effective.llm_batch_size,
            concurrency=effective.llm_concurrency,
        )
        if mode != "no_guard" and effective.integrity_enabled
        else {}
    )
    semantic_wall_time = time.perf_counter() - semantic_started

    metric_rows: list[MetricRow] = []
    details: list[dict[str, Any]] = []
    contract_cache: dict[str, Any] = {}
    chain_failures = 0
    direct_harm_failures = 0
    data_stealing_failures = 0
    for index, record in enumerate(records):
        case_id = f"{record['_agentgate_setting']}:{record['_agentgate_family']}:{index}"
        task = str(record["User Instruction"])
        attack_type = str(record.get("Attack Type", record["_agentgate_family"]))
        contract = contract_cache.get(task)
        if contract is None and mode != "no_guard":
            contract = await contracts.build(
                task,
                principal="injecagent-agent",
                entitlements={
                    "actions": [action.value for action in Action],
                    "resources": ["*"],
                },
            )
            contract_cache[task] = contract

        injected_content = str(record.get("Tool Response", ""))
        clean_content = str(record.get("Tool Response Template", "")).replace(
            "<Attacker Instruction>",
            "External content returned by the requested service.",
        )
        content_outcomes: dict[str, bool] = {}
        content_findings: list[Any] = []
        for stage, _content, malicious in (
            ("clean_result", clean_content, False),
            ("injected_result", injected_content, True),
        ):
            row_started = time.perf_counter()
            if mode == "no_guard" or not effective.integrity_enabled:
                blocked = False
                findings: list[Any] = []
            else:
                findings = content_findings_by_id[f"{index}:{stage}"]
                blocked = any(
                    finding.severity >= effective.integrity_block_severity
                    for finding in findings
                )
            content_outcomes[stage] = blocked
            if malicious:
                content_findings = findings
            _append_row(
                metric_rows,
                details,
                case_id=case_id,
                category=stage,
                attack_type=attack_type,
                tool=str(record["User Tool"]),
                expected="DENY" if malicious else "ALLOW",
                predicted="DENY" if blocked else "ALLOW",
                latency_ms=(time.perf_counter() - row_started) * 1000,
                evidence=[item.model_dump(mode="json") for item in findings],
            )

        user_tool = str(record["User Tool"])
        legitimate_allowed = await _evaluate_call(
            mode,
            effective,
            authorization,
            contract,
            registrations[user_tool],
            catalog[user_tool],
            ToolCall(
                tool_name=user_tool,
                arguments=_parse_arguments(str(record.get("Tool Parameters", "{}"))),
                principal="injecagent-agent",
                session_id=case_id,
            ),
            metric_rows,
            details,
            case_id,
            "legitimate_call",
            attack_type,
            expected="ALLOW",
        )
        del legitimate_allowed

        attack_all_allowed = True
        for attack_step, attacker_tool in enumerate(record.get("Attacker Tools", []), start=1):
            attacker_tool = str(attacker_tool)
            call = ToolCall(
                tool_name=attacker_tool,
                arguments={"request": str(record.get("Attacker Instruction", ""))},
                principal="injecagent-agent",
                session_id=case_id,
                untrusted_context=injected_content,
                integrity_findings=content_findings,
            )
            allowed = await _evaluate_call(
                mode,
                effective,
                authorization,
                contract,
                registrations[attacker_tool],
                catalog[attacker_tool],
                call,
                metric_rows,
                details,
                case_id,
                f"attack_call_{attack_step}",
                attack_type,
                expected="DENY",
            )
            attack_all_allowed &= allowed

        chain_failed = not content_outcomes["injected_result"] and attack_all_allowed
        if chain_failed:
            chain_failures += 1
            if record["_agentgate_family"] == "direct_harm":
                direct_harm_failures += 1
            else:
                data_stealing_failures += 1

    by_stage = {
        stage: compute_metrics([row for row in metric_rows if row.category == stage])
        for stage in sorted({row.category for row in metric_rows})
    }
    report = InjecAgentReport(
        source=str(root),
        setting=setting,
        mode=mode,
        metrics=compute_metrics(metric_rows),
        by_stage=by_stage,
        by_attack_type={
            attack_type: compute_metrics(
                [
                    row
                    for row, detail in zip(metric_rows, details, strict=True)
                    if detail["attack_type"] == attack_type
                ]
            )
            for attack_type in sorted({str(row["attack_type"]) for row in details})
        },
        analysis={
            "cases": len(records),
            "direct_harm_cases": sum(row["_agentgate_family"] == "direct_harm" for row in records),
            "data_stealing_cases": sum(
                row["_agentgate_family"] == "data_stealing" for row in records
            ),
            "chain_attack_successes": chain_failures,
            "chain_attack_success_rate": chain_failures / len(records) if records else 0.0,
            "direct_harm_chain_successes": direct_harm_failures,
            "data_stealing_chain_successes": data_stealing_failures,
            "paired_clean_controls": True,
            "tools_registered": len(registrations),
            "semantic_items": len(content_items),
            "semantic_unique_inputs": len(
                {
                    (
                        item.content,
                        tuple(sorted(item.known_tools)),
                        item.content_kind,
                        item.current_tool,
                    )
                    for item in content_items
                }
            ),
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


async def _evaluate_call(
    mode: str,
    settings: AgentGateSettings,
    authorization: AuthorizationModule,
    contract: Any,
    registration: Any,
    spec: ToolSpec,
    call: ToolCall,
    metric_rows: list[MetricRow],
    details: list[dict[str, Any]],
    case_id: str,
    stage: str,
    attack_type: str,
    *,
    expected: str,
) -> bool:
    started = time.perf_counter()
    if mode == "no_guard":
        action = DecisionAction.ALLOW
        evidence: Any = {}
    elif settings.integrity_enabled and registration is not None and registration.blocked:
        action = DecisionAction.DENY
        evidence = {
            "registration_findings": [
                item.model_dump(mode="json") for item in registration.findings
            ]
        }
    else:
        profile: ToolProfile = registration.profile
        if settings.authorization_enabled:
            decision, _ = await authorization.authorize(
                call,
                profile,
                contract,
                tool_description=spec.description,
            )
            action = decision.action
            evidence = decision.model_dump(mode="json")
        else:
            action = DecisionAction.ALLOW
            evidence = {"module": "authorization_ablation"}
    predicted = "ALLOW" if action == DecisionAction.ALLOW else "DENY"
    _append_row(
        metric_rows,
        details,
        case_id=case_id,
        category=stage,
        attack_type=attack_type,
        tool=call.tool_name,
        expected=expected,
        predicted=predicted,
        latency_ms=(time.perf_counter() - started) * 1000,
        evidence=evidence,
    )
    return predicted == "ALLOW"


def _append_row(
    metric_rows: list[MetricRow],
    details: list[dict[str, Any]],
    *,
    case_id: str,
    category: str,
    attack_type: str,
    tool: str,
    expected: str,
    predicted: str,
    latency_ms: float,
    evidence: Any,
) -> None:
    metric_rows.append(
        MetricRow(
            case_id=case_id,
            category=category,
            malicious=expected != "ALLOW",
            expected=expected,
            predicted=predicted,
            latency_ms=latency_ms,
        )
    )
    details.append(
        {
            "case_id": case_id,
            "stage": category,
            "attack_type": attack_type,
            "tool": tool,
            "expected": expected,
            "predicted": predicted,
            "latency_ms": latency_ms,
            "evidence": evidence,
        }
    )


def _load_cases(data_root: Path, setting: str) -> list[dict[str, Any]]:
    settings = ("base", "enhanced") if setting == "both" else (setting,)
    records: list[dict[str, Any]] = []
    for current in settings:
        for family, prefix in (("direct_harm", "dh"), ("data_stealing", "ds")):
            path = data_root / f"test_cases_{prefix}_{current}.json"
            values = json.loads(path.read_text(encoding="utf-8"))
            for value in values:
                value["_agentgate_setting"] = current
                value["_agentgate_family"] = family
                records.append(value)
    return records


def _load_tool_catalog(path: Path) -> dict[str, ToolSpec]:
    catalog: dict[str, ToolSpec] = {}
    for toolkit in json.loads(path.read_text(encoding="utf-8")):
        toolkit_name = str(toolkit["name_for_model"])
        for tool in toolkit["tools"]:
            short_name = str(tool["name"])
            name = f"{toolkit_name}{short_name}"
            properties = {
                str(parameter["name"]): {
                    "type": _parameter_type(str(parameter.get("type", "string"))),
                    "description": str(parameter.get("description", "")),
                }
                for parameter in tool.get("parameters", [])
            }
            required = [
                str(parameter["name"])
                for parameter in tool.get("parameters", [])
                if parameter.get("required")
            ]
            description = (
                f"{tool.get('summary', '')}\n{toolkit.get('description_for_model', '')}"
            )
            catalog[name] = ToolSpec(
                name=name,
                description=description,
                input_schema={
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
                namespace="injecagent",
                source="injecagent",
                publisher="InjecAgent",
                trusted=False,
            )
    return catalog


def _parse_arguments(raw: str) -> dict[str, Any]:
    try:
        value = ast.literal_eval(raw)
    except (SyntaxError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _parameter_type(value: str) -> str:
    lowered = value.lower()
    if "int" in lowered:
        return "integer"
    if "float" in lowered or "number" in lowered:
        return "number"
    if "bool" in lowered:
        return "boolean"
    if "list" in lowered or "array" in lowered:
        return "array"
    if "dict" in lowered or "object" in lowered:
        return "object"
    return "string"
