from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from agentgate.config import AgentGateSettings
from agentgate.evaluation.baselines import no_guard_prediction, static_policy_prediction
from agentgate.evaluation.cases import BenchmarkCase, load_cases, resolve_templates
from agentgate.evaluation.metrics import MetricRow, compute_metrics
from agentgate.models import ToolCall
from agentgate.runtime.gateway import AgentGate
from agentgate.tools import build_default_registry


class EvaluationReport(BaseModel):
    dataset: str
    mode: str
    metrics: dict[str, float | int]
    by_category: dict[str, dict[str, float | int]] = Field(default_factory=dict)
    rows: list[dict[str, Any]] = Field(default_factory=list)


async def evaluate_dataset(
    dataset: str | Path,
    *,
    mode: str = "full",
    split: str | None = None,
    settings: AgentGateSettings | None = None,
) -> EvaluationReport:
    cases = load_cases(dataset, split)
    rows: list[MetricRow] = []
    details: list[dict[str, Any]] = []
    for case in cases:
        case_rows, case_details = await _evaluate_case(case, mode, settings)
        rows.extend(case_rows)
        details.extend(case_details)
    categories = sorted({row.category for row in rows})
    return EvaluationReport(
        dataset=str(dataset),
        mode=mode,
        metrics=compute_metrics(rows),
        by_category={
            category: compute_metrics([row for row in rows if row.category == category])
            for category in categories
        },
        rows=details,
    )


async def _evaluate_case(
    case: BenchmarkCase,
    mode: str,
    base_settings: AgentGateSettings | None,
) -> tuple[list[MetricRow], list[dict[str, Any]]]:
    settings = (base_settings or AgentGateSettings.from_env()).model_copy(update=case.settings)
    settings.audit_path = Path(".agentgate/evaluation-audit.jsonl")
    registry, _ = build_default_registry()
    gateway = AgentGate.create(settings, registry)
    await gateway.initialize()
    rows: list[MetricRow] = []
    details: list[dict[str, Any]] = []

    if case.kind == "content":
        started = time.perf_counter()
        if mode == "no_guard" or mode == "static":
            predicted = "ALLOW"
            evidence: Any = []
        else:
            result = await gateway.integrity.inspect_result(case.content or "")
            predicted = "SANITIZE" if result.findings else "ALLOW"
            evidence = [item.model_dump(mode="json") for item in result.findings]
        rows.append(_row(case, "SANITIZE" if case.malicious else "ALLOW", predicted, started))
        expected = "SANITIZE" if case.malicious else "ALLOW"
        details.append(_detail(case, None, predicted, evidence, expected=expected))
        return rows, details

    if case.kind == "registration":
        started = time.perf_counter()
        if mode in {"no_guard", "static"}:
            predicted = "ALLOW"
            evidence = []
        else:
            assert case.tool_spec is not None
            result = await gateway.inspect_tool(case.tool_spec)
            predicted = "DENY" if result.blocked else "ALLOW"
            evidence = [item.model_dump(mode="json") for item in result.findings]
        expected = "DENY" if case.malicious else "ALLOW"
        rows.append(_row(case, expected, predicted, started))
        details.append(_detail(case, None, predicted, evidence, expected=expected))
        return rows, details

    if case.kind == "semantic_drift":
        started = time.perf_counter()
        if mode in {"no_guard", "static"}:
            predicted = "ALLOW"
            evidence = []
        else:
            result = None
            for spec in case.tool_versions:
                result = await gateway.inspect_tool(spec)
            assert result is not None
            predicted = "DENY" if result.blocked else "ALLOW"
            evidence = [item.model_dump(mode="json") for item in result.findings]
        expected = "DENY" if case.malicious else "ALLOW"
        rows.append(_row(case, expected, predicted, started))
        details.append(_detail(case, None, predicted, evidence, expected=expected))
        return rows, details

    assert case.contract is not None
    previous: Any = None
    for step in case.steps:
        started = time.perf_counter()
        if mode == "no_guard":
            predicted = no_guard_prediction(case, step)
            evidence = []
        elif mode == "static":
            profile = gateway.integrity.profile_for(step.tool)
            predicted = static_policy_prediction(case, step, profile)
            evidence = []
        else:
            try:
                arguments = resolve_templates(step.arguments, previous)
            except (KeyError, TypeError):
                predicted = "DENY"
                evidence = {"reason": "missing_previous_tool_output"}
                rows.append(_row(case, step.expected, predicted, started))
                details.append(
                    _detail(case, step.tool, predicted, evidence, expected=step.expected)
                )
                continue
            call = ToolCall(
                tool_name=step.tool,
                arguments=arguments,
                principal=case.contract.principal,
                session_id=case.id,
                approval_token=step.approval_token,
            )
            outcome = await gateway.execute(call, case.contract)
            predicted = outcome.decision.action.value
            evidence = outcome.decision.model_dump(mode="json")
            previous = outcome.result.output if outcome.result is not None else previous
        rows.append(_row(case, step.expected, predicted, started))
        details.append(_detail(case, step.tool, predicted, evidence, expected=step.expected))
    return rows, details


def _row(case: BenchmarkCase, expected: str, predicted: str, started: float) -> MetricRow:
    return MetricRow(
        case_id=case.id,
        category=case.category,
        malicious=case.malicious,
        expected=expected,
        predicted=predicted,
        latency_ms=(time.perf_counter() - started) * 1000,
    )


def _detail(
    case: BenchmarkCase,
    tool: str | None,
    predicted: str,
    evidence: Any,
    expected: str | None = None,
) -> dict[str, Any]:
    return {
        "case_id": case.id,
        "category": case.category,
        "risk_type": case.risk_type,
        "tool": tool,
        "expected": expected or ("DENY" if case.malicious else "ALLOW"),
        "predicted": predicted,
        "evidence": evidence,
    }
