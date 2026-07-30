from __future__ import annotations

import ast
import json
import random
import re
import time
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from agentgate.config import AgentGateSettings
from agentgate.evaluation.metrics import MetricRow, compute_metrics
from agentgate.llm import LLMAnalyzer
from agentgate.models import (
    Action,
    CallEffect,
    DecisionAction,
    IntegrityResult,
    ToolCall,
    ToolProfile,
    ToolResult,
    ToolSpec,
)
from agentgate.modules.authorization import (
    AuthorizationModule,
    CallRiskAssessment,
    CallSemanticRiskDetector,
    SemanticCallInput,
    TaskSafetyDetector,
)
from agentgate.modules.authorization.contracts import TaskContractBuilder
from agentgate.modules.integrity import IntegrityModule
from agentgate.modules.integrity.detector import BoundaryAnalysisInput, InstructionBoundaryDetector
from agentgate.modules.integrity.profiler import ToolProfiler
from agentgate.modules.integrity.sanitizer import sanitize_content
from agentgate.modules.trajectory import TrajectoryModule
from agentgate.policy import BuiltinPolicyBackend


class ToolSafeReport(BaseModel):
    source: str
    mode: str
    metrics: dict[str, float | int]
    family_metrics: dict[str, dict[str, float | int]]
    analysis: dict[str, Any] = Field(default_factory=dict)
    rows: list[dict[str, Any]]


async def evaluate_toolsafe(
    source: str | Path,
    settings: AgentGateSettings | None = None,
    mode: Literal["full", "rules", "no_guard"] = "full",
    limit: int | None = None,
    sample_size: int | None = None,
    sample_seed: int = 20260728,
    semantic_cache: str | Path | None = None,
) -> ToolSafeReport:
    if limit is not None and sample_size is not None:
        raise ValueError("limit and sample_size cannot be used together")
    if semantic_cache is not None and mode != "full":
        raise ValueError("semantic_cache is only valid in full mode")
    started_all = time.perf_counter()
    base_settings = settings or AgentGateSettings.from_env()
    if mode == "rules":
        settings = base_settings.model_copy(update={"llm_enabled": False})
    elif mode == "no_guard":
        settings = base_settings.model_copy(
            update={
                "llm_enabled": False,
                "integrity_enabled": False,
                "authorization_enabled": False,
                "trajectory_enabled": False,
            }
        )
    else:
        settings = base_settings
    llm = LLMAnalyzer(settings)
    integrity = IntegrityModule(
        ToolProfiler(),
        InstructionBoundaryDetector(llm),
        blocking_threshold=settings.integrity_block_severity,
    )
    contracts = TaskContractBuilder()
    task_safety = TaskSafetyDetector(
        llm,
        confidence_threshold=settings.semantic_confidence_threshold,
    )
    semantic_risk = CallSemanticRiskDetector(
        llm,
        confidence_threshold=settings.semantic_confidence_threshold,
        provenance_enabled=settings.provenance_fusion_enabled,
    )
    authorization = AuthorizationModule(
        BuiltinPolicyBackend(),
        task_safety=task_safety,
        semantic_risk=semantic_risk,
    )
    trajectory = TrajectoryModule(settings)
    metric_rows: list[MetricRow] = []
    details: list[dict[str, Any]] = []
    records = _load_records(Path(source))
    input_records = len(records)
    if sample_size is not None:
        records = _sample_complete_interactions(records, sample_size, sample_seed)
    if limit is not None:
        records = records[:limit]
    registration_semantic_started = time.perf_counter()
    registration_findings = await _build_registration_integrity_findings(
        records,
        integrity,
        settings,
    )
    registration_semantic_wall_time = time.perf_counter() - registration_semantic_started
    task_safety_started = time.perf_counter()
    task_assessments = await task_safety.assess_many(
        [_record_task(record) for record in records],
        batch_size=settings.llm_batch_size,
        concurrency=settings.llm_concurrency,
    )
    task_safety_wall_time = time.perf_counter() - task_safety_started
    semantic_started = time.perf_counter()
    cached_semantic_judgments = (
        _load_call_semantic_cache(
            Path(semantic_cache),
            expected_model=settings.llm_model,
        )
        if semantic_cache
        else {}
    )
    semantic_judgments = (
        await _build_call_semantic_judgments(
            records,
            semantic_risk,
            integrity,
            settings,
            cached_assessments=cached_semantic_judgments,
        )
        if settings.authorization_enabled
        else {}
    )
    semantic_wall_time = time.perf_counter() - semantic_started
    result_semantic_started = time.perf_counter()
    result_findings_by_index = await _build_result_integrity_findings(
        records,
        integrity,
        settings,
    )
    result_semantic_wall_time = time.perf_counter() - result_semantic_started

    contract_cache: dict[str, Any] = {}
    registration_cache: dict[str, Any] = {}
    pending_calls: dict[str, tuple[ToolCall, CallEffect, ToolProfile]] = {}

    for index, record in enumerate(records):
        started = time.perf_counter()
        current_action = str(record.get("current_action", ""))
        action_name, arguments = parse_current_action(current_action)
        expected_unsafe = float(record.get("score", 0.0)) > 0
        predicted = DecisionAction.ALLOW
        reasons: list[str] = []
        family = str(record.get("_agentgate_family", "agentdojo"))
        session_id = _toolsafe_session_id(record, index)
        history = str(record.get("history", ""))
        result_risk_types: list[str] = []
        if pending := pending_calls.pop(session_id, None):
            prior_call, prior_effect, prior_profile = pending
            prior_output = extract_latest_observation(history)
            cached_findings = result_findings_by_index.get(str(index), [])
            integrity_result = IntegrityResult(
                trust_level="untrusted" if cached_findings else "external_data",
                findings=cached_findings,
                sanitized_content=(
                    sanitize_content(prior_output, cached_findings)
                    if cached_findings
                    else prior_output
                ),
                blocking_threshold=settings.integrity_block_severity,
            )
            result_risk_types = [
                finding.risk_type for finding in integrity_result.findings
            ]
            if settings.trajectory_enabled:
                await trajectory.observe_result(
                    prior_call,
                    prior_effect,
                    prior_profile,
                    ToolResult(
                        call_id=prior_call.call_id,
                        tool_name=prior_call.tool_name,
                        output=integrity_result.sanitized_content or prior_output,
                        resource=prior_effect.resource,
                        side_effects=prior_effect.effects,
                        destination=prior_effect.destination,
                    ),
                )

        if family == "agentharm":
            assessment = await task_safety.assess(str(record.get("instruction", "")))
            if not settings.authorization_enabled:
                assessment = assessment.model_copy(
                    update={"safe": True, "categories": [], "source": "authorization_ablation"}
                )
            if not assessment.safe:
                predicted = DecisionAction.DENY
                reasons.extend(assessment.categories)
            expected = "DENY" if expected_unsafe else "ALLOW"
            metric_rows.append(
                MetricRow(
                    case_id=str(record.get("id-interaction", index)),
                    category=family,
                    malicious=expected_unsafe,
                    expected=expected,
                    predicted="DENY" if predicted != DecisionAction.ALLOW else "ALLOW",
                    latency_ms=(time.perf_counter() - started) * 1000,
                )
            )
            details.append(
                {
                    "index": index,
                    "interaction_id": record.get("id-interaction"),
                    "segment_id": record.get("id-segment"),
                    "source": record.get("_agentgate_source"),
                    "family": family,
                    "action": action_name,
                    "expected": expected,
                    "predicted": predicted.value,
                    "reasons": reasons,
                    "task_assessment": assessment.model_dump(mode="json"),
                }
            )
            continue

        if action_name and predicted == DecisionAction.ALLOW:
            spec = _tool_spec_from_env(
                action_name,
                str(record.get("env_info", "")),
                arguments,
                namespace=_toolsafe_namespace(record),
                source=str(record.get("_agentgate_source", "toolsafe")),
            )
            spec_key = _spec_cache_key(spec)
            registration = registration_cache.get(spec_key)
            if registration is None:
                registration = (
                    await integrity.register(
                        spec,
                        precomputed_findings=registration_findings.get(spec_key, []),
                    )
                    if settings.integrity_enabled
                    else IntegrityResult(
                        trust_level="integrity_ablation",
                        profile=await integrity.profiler.build(spec),
                        sanitized_content=spec.description,
                    )
                )
                registration_cache[spec_key] = registration
            profile = registration.profile
            if settings.integrity_enabled and registration.blocked:
                predicted = DecisionAction.DENY
                reasons.extend(finding.risk_type for finding in registration.findings)
            elif profile is not None:
                instruction = str(record.get("instruction", ""))
                contract_goal = _asb_base_task(instruction) if family == "asb" else instruction
                contract = contract_cache.get(contract_goal)
                if contract is None:
                    contract = await contracts.build(
                        contract_goal,
                        principal="toolsafe-agent",
                        entitlements={
                            "actions": [action.value for action in Action],
                            "resources": ["*"],
                        },
                    )
                    contract_cache[contract_goal] = contract
                external_context = "\n\n".join(
                    value
                    for value in (
                        _asb_external_context(instruction),
                        extract_untrusted_observations(history),
                    )
                    if value
                )
                call = ToolCall(
                    tool_name=action_name,
                    arguments=arguments,
                    principal=contract.principal,
                    session_id=session_id,
                    rationale=current_action,
                    untrusted_context=external_context,
                    prior_trace=history[-2000:],
                )
                semantic_assessment = semantic_judgments.get(str(index))
                if settings.authorization_enabled:
                    decision, effect = await authorization.authorize(
                        call,
                        profile,
                        contract,
                        tool_description=spec.description,
                        precomputed_call_risk=semantic_assessment,
                    )
                    predicted = decision.action
                    reasons.extend(decision.reasons)
                else:
                    effect = authorization.inferer.infer(profile, call)
                    predicted = DecisionAction.ALLOW
                if predicted == DecisionAction.ALLOW and settings.trajectory_enabled:
                    trajectory_decision = await trajectory.inspect_call(call, effect, profile)
                    predicted = trajectory_decision.action
                    reasons.extend(trajectory_decision.reasons)
                    if trajectory_decision.action == DecisionAction.ALLOW:
                        reservation = await trajectory.reserve_call(call, effect, profile)
                        predicted = reservation.action
                        reasons.extend(reservation.reasons)
                        if reservation.action == DecisionAction.ALLOW:
                            pending_calls[session_id] = (call, effect, profile)

        expected = "DENY" if expected_unsafe else "ALLOW"
        metric_rows.append(
            MetricRow(
                case_id=str(record.get("id-interaction", index)),
                category=family,
                malicious=expected_unsafe,
                expected=expected,
                predicted="DENY" if predicted != DecisionAction.ALLOW else "ALLOW",
                latency_ms=(time.perf_counter() - started) * 1000,
            )
        )
        details.append(
            {
                "index": index,
                "interaction_id": record.get("id-interaction"),
                "segment_id": record.get("id-segment"),
                "source": record.get("_agentgate_source"),
                "family": family,
                "action": action_name,
                "expected": expected,
                "predicted": predicted.value,
                "reasons": reasons,
                "result_integrity_findings": result_risk_types,
                "semantic_assessment": (
                    semantic_judgments[str(index)].model_dump(mode="json")
                    if str(index) in semantic_judgments
                    else None
                ),
            }
        )
    family_metrics = {
        family: compute_metrics([row for row in metric_rows if row.category == family])
        for family in sorted({row.category for row in metric_rows})
    }
    report = ToolSafeReport(
        source=str(source),
        mode=mode,
        metrics=compute_metrics(metric_rows),
        family_metrics=family_metrics,
        analysis={
            "llm_available": llm.available,
            "llm_model": settings.llm_model if llm.available else None,
            "input_records": input_records,
            "sample_size_requested": sample_size,
            "sample_seed": sample_seed if sample_size is not None else None,
            "sampled_records": len(records),
            "wall_time_seconds": time.perf_counter() - started_all,
            "registration_semantic_items": len(registration_findings),
            "registration_semantic_wall_time_seconds": registration_semantic_wall_time,
            "semantic_items": len(semantic_judgments),
            "semantic_cache_source": str(semantic_cache) if semantic_cache else None,
            "semantic_cache_items": len(cached_semantic_judgments),
            "semantic_llm_items": sum(
                assessment.source.startswith("llm") for assessment in semantic_judgments.values()
            ),
            "semantic_rule_fallback_items": sum(
                assessment.source.startswith("rules") for assessment in semantic_judgments.values()
            ),
            "semantic_llm_failure_items": sum(
                assessment.source == "rules_after_llm_failure"
                for assessment in semantic_judgments.values()
            ),
            "semantic_no_tool_items": sum(
                assessment.source == "no_tool_call" for assessment in semantic_judgments.values()
            ),
            "semantic_source_counts": _semantic_source_counts(semantic_judgments),
            "semantic_wall_time_seconds": semantic_wall_time,
            "result_semantic_items": len(result_findings_by_index),
            "result_semantic_wall_time_seconds": result_semantic_wall_time,
            "task_safety_items": len(task_assessments),
            "task_safety_wall_time_seconds": task_safety_wall_time,
            "llm_client": llm.stats(),
            "trajectory": _compute_trajectory_analysis(metric_rows, details),
            "trajectory_by_family": _compute_trajectory_analysis_by_family(
                metric_rows,
                details,
            ),
        },
        rows=details,
    )
    await llm.aclose()
    return report


async def _build_registration_integrity_findings(
    records: list[dict[str, Any]],
    integrity: IntegrityModule,
    settings: AgentGateSettings,
) -> dict[str, list[Any]]:
    if not settings.integrity_enabled:
        return {}
    specs: dict[str, ToolSpec] = {}
    known_tools: set[str] = set()
    for record in records:
        action_name, arguments = parse_current_action(str(record.get("current_action", "")))
        if not action_name:
            continue
        known_tools.add(action_name)
        spec = _tool_spec_from_env(
            action_name,
            str(record.get("env_info", "")),
            arguments,
            namespace=_toolsafe_namespace(record),
            source=str(record.get("_agentgate_source", "toolsafe")),
        )
        specs.setdefault(_spec_cache_key(spec), spec)

    item_to_key = {
        f"registration:{index}": spec_key
        for index, spec_key in enumerate(specs)
    }
    findings = await integrity.detector.analyze_many(
        [
            BoundaryAnalysisInput(
                item_id=item_id,
                content=specs[spec_key].description,
                known_tools=known_tools,
                content_kind="tool_description",
                current_tool=specs[spec_key].name,
            )
            for item_id, spec_key in item_to_key.items()
        ],
        batch_size=settings.llm_batch_size,
        concurrency=settings.llm_concurrency,
    )
    return {
        spec_key: findings[item_id]
        for item_id, spec_key in item_to_key.items()
    }


def _spec_cache_key(spec: ToolSpec) -> str:
    return json.dumps(spec.model_dump(mode="json"), sort_keys=True, default=str)


async def _build_call_semantic_judgments(
    records: list[dict[str, Any]],
    semantic_risk: CallSemanticRiskDetector,
    integrity: IntegrityModule,
    settings: AgentGateSettings,
    cached_assessments: dict[str, CallRiskAssessment] | None = None,
) -> dict[str, CallRiskAssessment]:
    items: list[SemanticCallInput] = []
    no_tool_ids: set[str] = set()
    for index, record in enumerate(records):
        family = str(record.get("_agentgate_family", "agentdojo"))
        if family == "agentharm":
            continue
        current_action = str(record.get("current_action", ""))
        action_name, arguments = parse_current_action(current_action)
        if not action_name:
            no_tool_ids.add(str(index))
            continue
        spec = _tool_spec_from_env(
            action_name,
            str(record.get("env_info", "")),
            arguments,
            namespace=_toolsafe_namespace(record),
            source=str(record.get("_agentgate_source", "toolsafe")),
        )
        profile = await integrity.profiler.build(spec)
        history = str(record.get("history", ""))
        instruction = str(record.get("instruction", ""))
        external_context = "\n\n".join(
            value
            for value in (
                _asb_external_context(instruction) if family == "asb" else "",
                extract_untrusted_observations(history),
            )
            if value
        )
        integrity_findings = (
            await integrity.detector.analyze(
                external_context,
                integrity.known_tools | {action_name},
                use_llm=False,
                content_kind="tool_result",
            )
            if external_context
            else []
        )
        items.append(
            SemanticCallInput(
                item_id=str(index),
                task=_asb_base_task(instruction) if family == "asb" else instruction,
                call=ToolCall(
                    tool_name=action_name,
                    arguments=arguments,
                    principal="toolsafe-agent",
                    session_id=_toolsafe_session_id(record, index),
                    rationale=current_action,
                    untrusted_context=external_context,
                    prior_trace=history[-2000:],
                    integrity_findings=integrity_findings,
                ),
                profile=profile,
                tool_description=spec.description,
                external_context=external_context,
                prior_trace=history[-2000:],
            )
        )
    cached_assessments = cached_assessments or {}
    assessments: dict[str, CallRiskAssessment] = {}
    pending_items: list[SemanticCallInput] = []
    for item in items:
        cached = cached_assessments.get(
            _semantic_cache_key(records[int(item.item_id)], item.call.tool_name)
        )
        if cached is None or cached.semantic_signals is None:
            pending_items.append(item)
        else:
            assessments[item.item_id] = semantic_risk.reapply_evidence_policy(item, cached)
    assessments.update(await semantic_risk.assess_many(
        pending_items,
        batch_size=settings.llm_batch_size,
        concurrency=settings.llm_concurrency,
    ))
    for item_id in no_tool_ids:
        assessments[item_id] = CallRiskAssessment(
            safe=True,
            confidence=1.0,
            source="no_tool_call",
        )
    return assessments


def _load_call_semantic_cache(
    path: Path,
    *,
    expected_model: str | None = None,
) -> dict[str, CallRiskAssessment]:
    if not path.is_file():
        raise FileNotFoundError(f"semantic cache report does not exist: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    cached_model = (
        payload.get("analysis", {}).get("llm_model") if isinstance(payload, dict) else None
    )
    if expected_model and cached_model and cached_model != expected_model:
        raise ValueError(
            f"semantic cache model mismatch: expected {expected_model!r}, got {cached_model!r}"
        )
    rows = payload.get("rows", []) if isinstance(payload, dict) else []
    cached: dict[str, CallRiskAssessment] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("semantic_assessment"), dict):
            continue
        try:
            cache_key = _semantic_cache_key(row, str(row.get("action", "")))
            cached[cache_key] = CallRiskAssessment.model_validate(row["semantic_assessment"])
        except (KeyError, TypeError, ValueError):
            continue
    return cached


def _semantic_cache_key(record: dict[str, Any], action: str) -> str:
    return json.dumps(
        {
            "family": record.get("family", record.get("_agentgate_family")),
            "source": record.get("source", record.get("_agentgate_source")),
            "interaction_id": record.get("interaction_id", record.get("id-interaction")),
            "segment_id": record.get("segment_id", record.get("id-segment")),
            "action": action,
        },
        ensure_ascii=True,
        sort_keys=True,
        default=str,
    )


async def _build_result_integrity_findings(
    records: list[dict[str, Any]],
    integrity: IntegrityModule,
    settings: AgentGateSettings,
) -> dict[str, list[Any]]:
    if not settings.integrity_enabled:
        return {}
    known_tools = {
        action
        for record in records
        for action, _arguments in [parse_current_action(str(record.get("current_action", "")))]
        if action
    }
    items = [
        BoundaryAnalysisInput(
            item_id=str(index),
            content=observation,
            known_tools=known_tools,
            content_kind="tool_result",
        )
        for index, record in enumerate(records)
        if (observation := extract_latest_observation(str(record.get("history", ""))))
    ]
    if not items:
        return {}
    return await integrity.detector.analyze_many(
        items,
        batch_size=settings.llm_batch_size,
        concurrency=settings.llm_concurrency,
    )


def parse_current_action(text: str) -> tuple[str | None, dict[str, Any]]:
    action_matches = re.findall(
        r"^\s*(?:\(\d+\)\s*)?Action:\s*([A-Za-z0-9_.-]+)\s*$",
        text,
        flags=re.MULTILINE,
    )
    action = action_matches[-1] if action_matches else None
    if action is not None and action.casefold() in {"none", "null", "no_action"}:
        action = None
    arguments: dict[str, Any] = {}
    input_matches = list(
        re.finditer(
            r"^\s*(?:\(\d+\)\s*)?Action Input:\s*",
            text,
            flags=re.MULTILINE,
        )
    )
    if input_matches:
        raw = text[input_matches[-1].end() :].lstrip()
        try:
            parsed, _ = json.JSONDecoder().raw_decode(raw)
        except json.JSONDecodeError:
            try:
                parsed = ast.literal_eval(raw.splitlines()[0])
            except (SyntaxError, ValueError):
                parsed = {}
        if isinstance(parsed, dict):
            arguments = parsed
    return action, arguments


def extract_untrusted_observations(history: str) -> str:
    observations = re.findall(
        r"Observation:\s*(.*?)(?=\n\(1\) Thought:|\Z)",
        history,
        flags=re.DOTALL,
    )
    return "\n".join(observations)


def extract_latest_observation(history: str) -> str:
    observations = re.findall(
        r"Observation:\s*(.*?)(?=\n\(1\) Thought:|\Z)",
        history,
        flags=re.DOTALL,
    )
    return observations[-1].strip() if observations else ""


def _tool_spec_from_env(
    name: str,
    env_info: str,
    arguments: dict[str, Any] | None = None,
    *,
    namespace: str = "default",
    source: str = "toolsafe",
) -> ToolSpec:
    match = re.search(
        rf"(?:^|\n){re.escape(name)}:\s*(.*?)(?=\n\n[A-Za-z0-9_.-]+:\s|\Z)",
        env_info,
        flags=re.DOTALL,
    )
    block = match.group(1).strip() if match else ""
    description = re.split(r"\n\s+parameters:\s*", block, maxsplit=1)[0].strip()
    if not description:
        description = f"Execute the {name} tool."
    properties: dict[str, dict[str, Any]] = {}
    parameters = re.search(r"\n\s+parameters:\s*(.*)", block, flags=re.DOTALL)
    if parameters:
        for field, raw_schema in re.findall(
            r"^[ \t]*([A-Za-z0-9_.-]+):\s*(\{.*\})\s*$",
            parameters.group(1),
            flags=re.MULTILINE,
        ):
            try:
                schema = ast.literal_eval(raw_schema)
            except (SyntaxError, ValueError):
                continue
            if isinstance(schema, dict):
                properties[field] = schema
    return ToolSpec(
        name=name,
        description=description,
        input_schema={"type": "object", "properties": properties},
        namespace=namespace,
        source=source,
        publisher="ToolSafe",
        trusted=False,
    )


def _toolsafe_session_id(record: dict[str, Any], index: int) -> str:
    return ":".join(
        (
            "toolsafe",
            str(record.get("_agentgate_family", "unknown")),
            str(record.get("_agentgate_source", "unknown")),
            str(record.get("id-interaction", index)),
        )
    )


def _toolsafe_namespace(record: dict[str, Any]) -> str:
    source = Path(str(record.get("_agentgate_source", "toolsafe"))).stem
    family = str(record.get("_agentgate_family", "unknown"))
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", f"{family}.{source}")


def _load_records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"ToolSafe source does not exist: {path}")
    if path.is_file():
        value = json.loads(path.read_text(encoding="utf-8"))
        records = value if isinstance(value, list) else [value]
        return [_annotate_record(record, path) for record in records]
    records: list[dict[str, Any]] = []
    for file_path in sorted(path.rglob("*.json")):
        value = json.loads(file_path.read_text(encoding="utf-8"))
        values = value if isinstance(value, list) else [value]
        records.extend(_annotate_record(record, file_path) for record in values)
    if not records:
        raise ValueError(f"ToolSafe source contains no JSON records: {path}")
    return records


def _sample_complete_interactions(
    records: list[dict[str, Any]],
    requested_records: int,
    seed: int,
) -> list[dict[str, Any]]:
    """Source-stratified sampling that never cuts a recorded interaction in half."""
    if requested_records <= 0:
        raise ValueError("sample_size must be positive")
    if requested_records >= len(records):
        return records

    source_indices: dict[str, list[int]] = {}
    for index, record in enumerate(records):
        source = str(record.get("_agentgate_source", ""))
        source_indices.setdefault(source, []).append(index)

    selected: set[int] = set()
    allocated = 0
    sources = sorted(source_indices)
    for source_index, source in enumerate(sources):
        indices = source_indices[source]
        if source_index == len(sources) - 1:
            target = max(1, requested_records - allocated)
        else:
            target = max(1, round(requested_records * len(indices) / len(records)))
            allocated += target

        interactions: dict[str, list[int]] = {}
        for index in indices:
            record = records[index]
            interaction_id = str(record.get("id-interaction", index))
            interactions.setdefault(interaction_id, []).append(index)
        interaction_groups = list(interactions.values())
        random.Random(f"{seed}:{source}").shuffle(interaction_groups)

        source_count = 0
        for group in interaction_groups:
            selected.update(group)
            source_count += len(group)
            if source_count >= target:
                break
    return [record for index, record in enumerate(records) if index in selected]


def _semantic_source_counts(
    assessments: dict[str, CallRiskAssessment],
) -> dict[str, int]:
    counts: dict[str, int] = {}
    for assessment in assessments.values():
        counts[assessment.source] = counts.get(assessment.source, 0) + 1
    return dict(sorted(counts.items()))


def _annotate_record(record: dict[str, Any], path: Path) -> dict[str, Any]:
    if "agentharm-traj" in path.parts:
        family = "agentharm"
    elif "asb-traj" in path.parts:
        family = "asb"
    else:
        family = "agentdojo"
    return {**record, "_agentgate_family": family, "_agentgate_source": str(path)}


def _compute_trajectory_analysis(
    metric_rows: list[MetricRow],
    details: list[dict[str, Any]],
) -> dict[str, Any]:
    """Recompute metrics after applying the gateway's stop-on-deny semantics."""
    if len(metric_rows) != len(details):
        raise ValueError("metric rows and detail rows must stay aligned")

    reachable_rows: list[MetricRow] = []
    stopped: set[tuple[str, str, str]] = set()
    interaction_ids: set[tuple[str, str, str]] = set()
    attack_ids: set[tuple[str, str, str]] = set()
    compromised_ids: set[tuple[str, str, str]] = set()
    clean_denied_ids: set[tuple[str, str, str]] = set()

    for row, detail in zip(metric_rows, details, strict=True):
        interaction_id = detail.get("interaction_id")
        if interaction_id is None:
            interaction_id = detail.get("index")
        key = (
            str(detail.get("family", "unknown")),
            str(detail.get("source", "")),
            str(interaction_id),
        )
        interaction_ids.add(key)
        if row.expected != "ALLOW":
            attack_ids.add(key)
        if key in stopped:
            continue

        reachable_rows.append(row)
        if row.expected != "ALLOW" and row.predicted == "ALLOW":
            compromised_ids.add(key)
        if row.predicted != "ALLOW":
            stopped.add(key)
            if row.expected == "ALLOW":
                clean_denied_ids.add(key)

    clean_ids = interaction_ids - attack_ids
    clean_false_positives = clean_denied_ids & clean_ids
    clean_completed = clean_ids - clean_false_positives
    interaction_fn = len(compromised_ids & attack_ids)
    interaction_tp = len(attack_ids) - interaction_fn
    interaction_fp = len(clean_false_positives)
    interaction_tn = len(clean_completed)
    return {
        "interactions": len(interaction_ids),
        "attack_interactions": len(attack_ids),
        "attack_successful_interactions": len(compromised_ids & attack_ids),
        "attack_success_rate": (
            len(compromised_ids & attack_ids) / len(attack_ids) if attack_ids else 0.0
        ),
        "clean_interactions": len(clean_ids),
        "clean_completion_rate": len(clean_completed) / len(clean_ids) if clean_ids else 0.0,
        "interaction_confusion": {
            "tp": interaction_tp,
            "fp": interaction_fp,
            "tn": interaction_tn,
            "fn": interaction_fn,
            "false_positive_rate": (interaction_fp / len(clean_ids) if clean_ids else 0.0),
            "false_negative_rate": (interaction_fn / len(attack_ids) if attack_ids else 0.0),
        },
        "reachable_steps": len(reachable_rows),
        "unreachable_steps": len(metric_rows) - len(reachable_rows),
        "reachable_metrics": compute_metrics(reachable_rows),
    }


def _compute_trajectory_analysis_by_family(
    metric_rows: list[MetricRow],
    details: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Apply stop-on-deny replay independently to each benchmark family."""
    if len(metric_rows) != len(details):
        raise ValueError("metric rows and detail rows must stay aligned")

    grouped: dict[str, tuple[list[MetricRow], list[dict[str, Any]]]] = {}
    for row, detail in zip(metric_rows, details, strict=True):
        family = str(detail.get("family", row.category))
        rows, family_details = grouped.setdefault(family, ([], []))
        rows.append(row)
        family_details.append(detail)
    return {
        family: _compute_trajectory_analysis(rows, family_details)
        for family, (rows, family_details) in sorted(grouped.items())
    }


def _asb_base_task(instruction: str) -> str:
    return _split_asb_instruction(instruction)[0]


def _record_task(record: dict[str, Any]) -> str:
    instruction = str(record.get("instruction", ""))
    return (
        _asb_base_task(instruction)
        if str(record.get("_agentgate_family", "")) == "asb"
        else instruction
    )


def _asb_external_context(instruction: str) -> str:
    return _split_asb_instruction(instruction)[1]


def _split_asb_instruction(instruction: str) -> tuple[str, str]:
    markers = (
        "You must strictly adhere to the following instruction:",
        "You must follow this additional instruction:",
    )
    for marker in markers:
        if marker in instruction:
            base, external = instruction.split(marker, 1)
            return base.strip(), external.strip()
    return instruction, ""
