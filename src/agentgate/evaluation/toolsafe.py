from __future__ import annotations

import ast
import json
import re
import time
from collections import Counter
from pathlib import Path
from typing import Any, Literal

from agentgate.authorization import (
    TaskAuthorizationCompiler,
    TaskAuthorizer,
    TaskIntent,
)
from agentgate.capabilities import CapabilityInferer
from agentgate.content import ContentScanner
from agentgate.evaluation.metrics import MetricRow, compute_metrics
from agentgate.events import EffectType, RawToolCall, SecurityOperation, ToolEventBuilder

ToolSafeMode = Literal["agentgate", "static_acl", "no_guard"]


async def evaluate_toolsafe(source: str | Path, mode: ToolSafeMode) -> dict:
    root = Path(source)
    paths = sorted((root / "TS-Bench" / "agentdojo-traj").glob("*.json"))
    inferer = CapabilityInferer()
    compiler = TaskAuthorizationCompiler()
    authorizer = TaskAuthorizer()
    builder = ToolEventBuilder()
    scanner = ContentScanner()
    rows: list[MetricRow] = []
    by_domain: dict[str, list[MetricRow]] = {}
    parse_failures = 0
    capability_cache: dict[tuple[str, str], Any] = {}
    authorization_cache: dict[str, Any] = {}
    outcome_causes: Counter[tuple[str, str]] = Counter()
    misclassified_actions: dict[str, Counter[str]] = {
        "false_positive": Counter(),
        "false_negative": Counter(),
    }
    for path in paths:
        records = json.loads(path.read_text(encoding="utf-8"))
        for index, record in enumerate(records):
            started = time.perf_counter()
            action, arguments = parse_current_action(str(record.get("current_action", "")))
            expected_unsafe = float(record.get("score", 0)) > 0
            predicted_unsafe = False
            causes: list[str] = []
            history = str(record.get("history", ""))
            content_analysis = scanner.scan(history)
            context_match = bool(
                action
                and content_analysis.blocked
                and _untrusted_content_references_action(action, history)
            )
            if context_match and mode == "agentgate":
                predicted_unsafe = True
                causes.append("untrusted_history_tool_reference")
            if action is None:
                parse_failures += 1
                causes.append("action_parse_failure")
            elif mode != "no_guard":
                description = _tool_description(action, str(record.get("env_info", "")))
                cache_key = (action, description)
                capability = capability_cache.get(cache_key)
                if capability is None:
                    schema = {
                        "type": "object",
                        "properties": {
                            key: {"type": _json_type(value)} for key, value in arguments.items()
                        },
                    }
                    try:
                        capability = await inferer.infer(
                            name=action,
                            description=description,
                            input_schema=schema,
                        )
                    except ValueError:
                        capability = None
                    capability_cache[cache_key] = capability
                if capability is None:
                    causes.append("capability_inference_failure")
                else:
                    goal = str(record.get("instruction", ""))
                    authorization = authorization_cache.get(goal)
                    if authorization is None:
                        authorization = compiler.compile(
                            TaskIntent(task_id="toolsafe-task", goal=goal),
                            principal="toolsafe-agent",
                            entitlements={
                                "operations": [item.value for item in SecurityOperation],
                                "resources": ["*"],
                                "effects": [item.value for item in EffectType],
                                "destinations": ["*"],
                                "max_records": 100,
                            },
                            issuer="offline-toolsafe-evaluator",
                        )
                        authorization_cache[goal] = authorization
                    event = builder.build_request(
                        RawToolCall(
                            tool_name=action,
                            arguments=arguments,
                            principal="toolsafe-agent",
                            session_id=f"{path.stem}:{record.get('id-interaction', index)}",
                            task_id="toolsafe-task",
                        ),
                        capability,
                    )
                    authorization = _extend_authorization_from_trusted_history(
                        authorization,
                        event_resource=event.resource_id,
                        event_destination=event.destination,
                        arguments=arguments,
                        history=_trusted_history(history),
                    )
                    if mode == "static_acl":
                        acl_mismatch = event.operation not in authorization.allowed_operations
                        predicted_unsafe = predicted_unsafe or acl_mismatch
                        if acl_mismatch:
                            causes.append("task_authorization_operation")
                    else:
                        decision = authorizer.evaluate(event, authorization)
                        authorization_mismatch = decision.action != "ALLOW"
                        predicted_unsafe = predicted_unsafe or authorization_mismatch
                        causes.extend(decision.rule_ids)
            row = MetricRow(
                case_id=f"{path.stem}:{index}",
                category=path.stem,
                expected_unsafe=expected_unsafe,
                predicted_unsafe=predicted_unsafe,
                latency_ms=(time.perf_counter() - started) * 1000,
            )
            rows.append(row)
            by_domain.setdefault(path.stem, []).append(row)
            outcome = _outcome_name(expected_unsafe, predicted_unsafe)
            for cause in causes or ["no_security_evidence"]:
                outcome_causes[(outcome, cause)] += 1
            if expected_unsafe and not predicted_unsafe:
                misclassified_actions["false_negative"][action or "<unparsed>"] += 1
            elif not expected_unsafe and predicted_unsafe:
                misclassified_actions["false_positive"][action or "<unparsed>"] += 1
    return {
        "benchmark": "TS-Bench/AgentDojo-Traj",
        "revision": "46358fa424a927a895c6c8322f99032c4eb5155e",
        "mode": mode,
        "metrics": compute_metrics(rows),
        "by_domain": {name: compute_metrics(items) for name, items in by_domain.items()},
        "parse_failures": parse_failures,
        "error_analysis": {
            outcome: {
                cause: count
                for (row_outcome, cause), count in sorted(outcome_causes.items())
                if row_outcome == outcome
            }
            for outcome in ("true_positive", "false_positive", "true_negative", "false_negative")
        },
        "top_misclassified_actions": {
            outcome: dict(counter.most_common(20))
            for outcome, counter in misclassified_actions.items()
        },
    }


def parse_current_action(text: str) -> tuple[str | None, dict[str, Any]]:
    action = re.search(r"\(2\) Action:\s*([^\n]+)", text)
    arguments = re.search(r"\(3\) Action Input:\s*(.+)\s*$", text, re.DOTALL)
    if not action:
        return None, {}
    raw = arguments.group(1).strip() if arguments else "{}"
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        try:
            parsed = ast.literal_eval(raw)
        except (SyntaxError, ValueError):
            parsed = {}
    return action.group(1).strip(), parsed if isinstance(parsed, dict) else {}


def _tool_description(name: str, env_info: str) -> str:
    match = re.search(
        rf"(?:^|\n\n){re.escape(name)}:\s*(.*?)(?=\n\n[A-Za-z_][\w-]*:|\Z)",
        env_info,
        re.DOTALL,
    )
    return match.group(1).strip() if match else name.replace("_", " ")


def _json_type(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "string"


def _destinations_in_arguments(arguments: dict[str, Any]) -> list[str]:
    return [
        rendered
        for key, value in arguments.items()
        if any(
            word in key.lower()
            for word in (
                "destination",
                "recipient",
                "address",
                "url",
                "endpoint",
                "account",
                "channel",
            )
        )
        for rendered in _scalar_strings(value)
    ]


def _scalar_strings(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [item for child in value.values() for item in _scalar_strings(child)]
    if isinstance(value, (list, tuple, set)):
        return [item for child in value for item in _scalar_strings(child)]
    if value is None or isinstance(value, bool):
        return []
    return [str(value)]


def _untrusted_content_references_action(action: str, history: str) -> bool:
    normalized = action.strip()
    if not normalized:
        return False
    sections = re.findall(
        r"<INFORMATION>(.*?)</INFORMATION>",
        history,
        flags=re.IGNORECASE | re.DOTALL,
    )
    haystacks = sections or [history]
    pattern = re.compile(rf"(?<![\w-]){re.escape(normalized)}(?![\w-])", re.IGNORECASE)
    return any(pattern.search(section) for section in haystacks)


def _trusted_history(history: str) -> str:
    return re.sub(
        r"<INFORMATION>.*?</INFORMATION>",
        "",
        history,
        flags=re.IGNORECASE | re.DOTALL,
    )


def _extend_authorization_from_trusted_history(
    authorization,
    *,
    event_resource: str | None,
    event_destination: str | None,
    arguments: dict[str, Any],
    history: str,
):
    resources = set(authorization.allowed_resource_patterns)
    destinations = set(authorization.allowed_destinations)
    if event_resource and _history_contains_value(history, event_resource):
        resources.add(event_resource)
    destination_values = _destinations_in_arguments(arguments)
    if (
        event_destination
        and destination_values
        and all(_history_contains_value(history, value) for value in destination_values)
    ):
        destinations.add(event_destination)
    return authorization.model_copy(
        update={
            "allowed_resource_patterns": sorted(resources),
            "allowed_destinations": sorted(destinations),
        }
    )


def _history_contains_value(history: str, value: str) -> bool:
    rendered = value.strip()
    return len(rendered) >= 2 and rendered.lower() in history.lower()


def _outcome_name(expected_unsafe: bool, predicted_unsafe: bool) -> str:
    if expected_unsafe:
        return "true_positive" if predicted_unsafe else "false_negative"
    return "false_positive" if predicted_unsafe else "true_negative"
