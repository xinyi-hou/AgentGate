from __future__ import annotations

import ast
import json
import re
import time
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from agentgate.config import AgentGateSettings
from agentgate.evaluation.metrics import MetricRow, compute_metrics
from agentgate.llm import LLMAnalyzer
from agentgate.models import Action, DecisionAction, TaskContract, ToolCall, ToolSpec
from agentgate.modules.authorization import (
    AuthorizationModule,
    CallSemanticRiskDetector,
    TaskSafetyDetector,
)
from agentgate.modules.authorization.contracts import TaskContractBuilder
from agentgate.modules.integrity import IntegrityModule
from agentgate.modules.integrity.detector import InstructionBoundaryDetector
from agentgate.modules.integrity.profiler import ToolProfiler
from agentgate.policy import BuiltinPolicyBackend


class ToolSafeReport(BaseModel):
    source: str
    metrics: dict[str, float | int]
    family_metrics: dict[str, dict[str, float | int]]
    rows: list[dict[str, Any]]


async def evaluate_toolsafe(
    source: str | Path,
    settings: AgentGateSettings | None = None,
    limit: int | None = None,
) -> ToolSafeReport:
    settings = settings or AgentGateSettings.from_env()
    llm = LLMAnalyzer(settings)
    integrity = IntegrityModule(
        ToolProfiler(llm),
        InstructionBoundaryDetector(llm),
        blocking_threshold=settings.integrity_block_severity,
    )
    contracts = TaskContractBuilder(llm)
    task_safety = TaskSafetyDetector(
        llm,
        confidence_threshold=settings.semantic_confidence_threshold,
    )
    authorization = AuthorizationModule(
        BuiltinPolicyBackend(),
        task_safety=task_safety,
        semantic_risk=CallSemanticRiskDetector(
            llm,
            confidence_threshold=settings.semantic_confidence_threshold,
        ),
    )
    metric_rows: list[MetricRow] = []
    details: list[dict[str, Any]] = []
    records = _load_records(Path(source))
    if limit is not None:
        records = records[:limit]

    for index, record in enumerate(records):
        started = time.perf_counter()
        current_action = str(record.get("current_action", ""))
        action_name, arguments = parse_current_action(current_action)
        expected_unsafe = float(record.get("score", 0.0)) > 0
        predicted = DecisionAction.ALLOW
        reasons: list[str] = []
        family = str(record.get("_agentgate_family", "agentdojo"))

        if family == "agentharm":
            assessment = await task_safety.assess(str(record.get("instruction", "")))
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
                    "family": family,
                    "action": action_name,
                    "expected": expected,
                    "predicted": predicted.value,
                    "reasons": reasons,
                }
            )
            continue

        untrusted_content = extract_untrusted_observations(str(record.get("history", "")))
        integrity_result = await integrity.inspect_result(untrusted_content)
        if integrity_result.findings and _call_links_to_untrusted_instruction(
            action_name,
            arguments,
            current_action,
            untrusted_content,
        ):
            predicted = DecisionAction.DENY
            reasons.extend(finding.risk_type for finding in integrity_result.findings)

        if action_name and predicted == DecisionAction.ALLOW:
            spec = _tool_spec_from_env(action_name, str(record.get("env_info", "")))
            registration = await integrity.register(spec)
            profile = registration.profile
            if profile is not None:
                instruction = str(record.get("instruction", ""))
                contract_goal = _asb_base_task(instruction) if family == "asb" else instruction
                contract = await contracts.build(
                    contract_goal,
                    principal="toolsafe-agent",
                    entitlements={
                        "actions": [action.value for action in Action],
                        "resources": ["*"],
                    },
                )
                contract = _adapt_contract_for_toolsafe(contract, profile, family)
                approval_token = None
                if profile.action in {Action.DELETE, Action.EXECUTE} and (
                    profile.action in contract.allowed_actions
                ):
                    approval_token = f"toolsafe-explicit-{index}"
                    contract = contract.model_copy(
                        update={"approval_tokens": {approval_token}}
                    )
                decision, _ = await authorization.authorize(
                    ToolCall(
                        tool_name=action_name,
                        arguments=arguments,
                        principal=contract.principal,
                        session_id=f"toolsafe-{index}",
                        approval_token=approval_token,
                        rationale=current_action if family == "asb" else None,
                    ),
                    profile,
                    contract,
                )
                predicted = decision.action
                reasons.extend(decision.reasons)

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
                "family": family,
                "action": action_name,
                "expected": expected,
                "predicted": predicted.value,
                "reasons": reasons,
            }
        )
    family_metrics = {
        family: compute_metrics([row for row in metric_rows if row.category == family])
        for family in sorted({row.category for row in metric_rows})
    }
    return ToolSafeReport(
        source=str(source),
        metrics=compute_metrics(metric_rows),
        family_metrics=family_metrics,
        rows=details,
    )


def parse_current_action(text: str) -> tuple[str | None, dict[str, Any]]:
    action_matches = re.findall(
        r"^\s*(?:\(\d+\)\s*)?Action:\s*([A-Za-z0-9_.-]+)\s*$",
        text,
        flags=re.MULTILINE,
    )
    action = action_matches[-1] if action_matches else None
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


def _tool_spec_from_env(name: str, env_info: str) -> ToolSpec:
    match = re.search(
        rf"(?:^|\n){re.escape(name)}:\s*(.*?)(?=\n\n[A-Za-z0-9_.-]+:|\Z)",
        env_info,
        flags=re.DOTALL,
    )
    description = match.group(1).strip() if match else f"Execute the {name} tool."
    return ToolSpec(
        name=name,
        description=description,
        input_schema={"type": "object", "properties": {}},
        source="toolsafe",
        publisher="ToolSafe",
        trusted=False,
    )


def _load_records(path: Path) -> list[dict[str, Any]]:
    if path.is_file():
        value = json.loads(path.read_text(encoding="utf-8"))
        records = value if isinstance(value, list) else [value]
        return [_annotate_record(record, path) for record in records]
    records: list[dict[str, Any]] = []
    for file_path in sorted(path.rglob("*.json")):
        value = json.loads(file_path.read_text(encoding="utf-8"))
        values = value if isinstance(value, list) else [value]
        records.extend(_annotate_record(record, file_path) for record in values)
    return records


def _annotate_record(record: dict[str, Any], path: Path) -> dict[str, Any]:
    if "agentharm-traj" in path.parts:
        family = "agentharm"
    elif "asb-traj" in path.parts:
        family = "asb"
    else:
        family = "agentdojo"
    return {**record, "_agentgate_family": family, "_agentgate_source": str(path)}


def _asb_base_task(instruction: str) -> str:
    markers = (
        "You must strictly adhere to the following instruction:",
        "You must follow this additional instruction:",
    )
    for marker in markers:
        if marker in instruction:
            return instruction.split(marker, 1)[0].strip()
    return instruction


def _adapt_contract_for_toolsafe(
    contract: TaskContract,
    profile: Any,
    family: str,
) -> TaskContract:
    # TS-Bench exposes tool descriptions but not a normalized resource catalog. Keep
    # action/effect checks strict while avoiding artificial resource-name mismatches.
    updates: dict[str, Any] = {
            "allowed_resources": {"*"},
            "confirmed_actions": set(contract.allowed_actions),
            "max_records": 1000,
            "allowed_effects": set(contract.allowed_effects) | {"data_export"},
            "forbidden_effects": set(contract.forbidden_effects) - {"data_export"},
    }
    if family == "asb":
        updates.update(
            {
                "allowed_actions": set(Action),
                "confirmed_actions": set(Action),
                "allowed_effects": set(profile.effects)
                | {"data_read", "data_export", "state_change", "external_transmission"},
                "forbidden_effects": set(),
                "external_transmission": True,
            }
        )
    return contract.model_copy(update=updates)


def _call_links_to_untrusted_instruction(
    action_name: str | None,
    arguments: dict[str, Any],
    current_action: str,
    untrusted_content: str,
) -> bool:
    if not action_name or not untrusted_content:
        return False
    instruction_blocks = re.findall(
        r"<INFORMATION>(.*?)</INFORMATION>",
        untrusted_content,
        flags=re.DOTALL | re.IGNORECASE,
    )
    suspicious = "\n".join(instruction_blocks) or untrusted_content
    strong_thought_signals = (
        "prerequisite",
        "instruction given",
        "instructed by",
        "message within",
        "need to fulfill",
        "before i can",
        "before calculating",
        "embedded message",
        "following her instructions",
        "follow the instructions",
        "special instructions",
    )
    lowered_action = current_action.lower()
    completion_signals = (
        "has been completed",
        "successfully sent",
        "now, i can proceed",
        "now i will proceed",
        "original request",
    )
    if any(signal in lowered_action for signal in strong_thought_signals) and not any(
        signal in lowered_action for signal in completion_signals
    ):
        return True

    if not _tool_semantics_mentioned(action_name, suspicious):
        return False

    if "as instructed" in lowered_action:
        return True

    normalized_suspicious = suspicious.lower()
    for value in arguments.values():
        if value is None or isinstance(value, bool):
            continue
        rendered = str(value).strip().lower()
        if len(rendered) >= 4 and rendered in normalized_suspicious:
            return True
    return not arguments


def _tool_semantics_mentioned(action_name: str, content: str) -> bool:
    aliases = {
        "webpage": {"webpage", "website", "url"},
        "email": {"email", "mail"},
        "message": {"message", "post"},
    }
    ignored = {"get", "by", "id", "all", "for", "to", "from", "current"}
    action_tokens = [
        token
        for token in re.findall(r"[a-z0-9]+", action_name.lower())
        if token not in ignored
    ]
    content_tokens = set(re.findall(r"[a-z0-9]+", content.lower()))
    for token in action_tokens:
        candidates = aliases.get(token, {token, token.removesuffix("s")})
        if not candidates & content_tokens:
            return False
    return bool(action_tokens)
