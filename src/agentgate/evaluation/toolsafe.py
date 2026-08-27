from __future__ import annotations

import ast
import json
import re
import time
from pathlib import Path
from typing import Any, Literal

from agentgate.authorization import TaskAuthorizer, TaskContractCompiler
from agentgate.capabilities import CapabilityInferer
from agentgate.evaluation.metrics import MetricRow, compute_metrics
from agentgate.events import RawToolCall, ToolEventBuilder

ToolSafeMode = Literal["agentgate", "static_acl", "no_guard"]


async def evaluate_toolsafe(source: str | Path, mode: ToolSafeMode) -> dict:
    root = Path(source)
    paths = sorted((root / "TS-Bench" / "agentdojo-traj").glob("*.json"))
    inferer = CapabilityInferer()
    compiler = TaskContractCompiler()
    authorizer = TaskAuthorizer()
    builder = ToolEventBuilder()
    rows: list[MetricRow] = []
    by_domain: dict[str, list[MetricRow]] = {}
    parse_failures = 0
    capability_cache: dict[tuple[str, str], Any] = {}
    contract_cache: dict[str, Any] = {}
    for path in paths:
        records = json.loads(path.read_text(encoding="utf-8"))
        for index, record in enumerate(records):
            started = time.perf_counter()
            action, arguments = parse_current_action(str(record.get("current_action", "")))
            expected_unsafe = float(record.get("score", 0)) > 0
            predicted_unsafe = False
            if action is None:
                parse_failures += 1
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
                if capability is not None:
                    goal = str(record.get("instruction", ""))
                    contract = contract_cache.get(goal)
                    if contract is None:
                        contract = compiler.compile(goal, principal="toolsafe-agent")
                        contract_cache[goal] = contract
                    event = builder.build_request(
                        RawToolCall(
                            tool_name=action,
                            arguments=arguments,
                            principal="toolsafe-agent",
                            session_id=f"{path.stem}:{record.get('id-interaction', index)}",
                        ),
                        capability,
                    )
                    if mode == "static_acl":
                        predicted_unsafe = event.operation not in contract.allowed_operations
                    else:
                        predicted_unsafe = authorizer.evaluate(event, contract).action != "ALLOW"
            row = MetricRow(
                case_id=f"{path.stem}:{index}",
                category=path.stem,
                expected_unsafe=expected_unsafe,
                predicted_unsafe=predicted_unsafe,
                latency_ms=(time.perf_counter() - started) * 1000,
            )
            rows.append(row)
            by_domain.setdefault(path.stem, []).append(row)
    return {
        "benchmark": "TS-Bench/AgentDojo-Traj",
        "revision": "46358fa424a927a895c6c8322f99032c4eb5155e",
        "mode": mode,
        "metrics": compute_metrics(rows),
        "by_domain": {name: compute_metrics(items) for name, items in by_domain.items()},
        "parse_failures": parse_failures,
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
