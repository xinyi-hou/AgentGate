from __future__ import annotations

import ast
import json
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
from agentgate.modules.integrity.detector import InstructionBoundaryDetector
from agentgate.modules.integrity.profiler import ToolProfiler
from agentgate.modules.trajectory import TrajectoryModule
from agentgate.policy import BuiltinPolicyBackend


class Tau2Report(BaseModel):
    source: str
    mode: str
    metrics: dict[str, float | int]
    by_domain: dict[str, dict[str, float | int]] = Field(default_factory=dict)
    trajectory_metrics: dict[str, float | int] = Field(default_factory=dict)
    analysis: dict[str, Any] = Field(default_factory=dict)
    rows: list[dict[str, Any]] = Field(default_factory=list)


async def evaluate_tau2(
    source: str | Path,
    *,
    settings: AgentGateSettings | None = None,
    mode: Literal["full", "rules", "no_guard"] = "full",
    limit: int | None = None,
) -> Tau2Report:
    root = Path(source)
    results_root = root / "data/tau2/results/final"
    domains_root = root / "src/tau2/domains"
    if not results_root.is_dir() or not domains_root.is_dir():
        raise FileNotFoundError(f"invalid tau2-bench checkout: {root}")

    base_settings = settings or AgentGateSettings.from_env()
    effective = (
        base_settings.model_copy(update={"llm_enabled": False})
        if mode == "rules"
        else base_settings
    )
    llm = LLMAnalyzer(effective)
    profiler = ToolProfiler(llm)
    integrity = IntegrityModule(
        profiler,
        InstructionBoundaryDetector(llm),
        blocking_threshold=effective.integrity_block_severity,
    )
    authorization = AuthorizationModule(
        BuiltinPolicyBackend(),
        task_safety=TaskSafetyDetector(llm),
        semantic_risk=CallSemanticRiskDetector(
            llm,
            provenance_enabled=effective.provenance_fusion_enabled,
        ),
    )
    trajectory = TrajectoryModule(effective, llm=llm)
    contracts = TaskContractBuilder(llm)
    definitions = _load_domain_definitions(domains_root)
    registrations: dict[tuple[str, str], Any] = {}
    contract_cache: dict[tuple[str, str], Any] = {}
    metric_rows: list[MetricRow] = []
    details: list[dict[str, Any]] = []
    trajectory_outcomes: dict[str, bool] = {}
    successful_simulations = 0
    total_simulations = 0
    stopped = False
    started_all = time.perf_counter()

    for result_path in sorted(results_root.glob("*.json")):
        payload = json.loads(result_path.read_text(encoding="utf-8"))
        environment_info = payload.get("info", {}).get("environment_info", {})
        domain = str(environment_info.get("domain_name", "unknown"))
        policy_context = _compact_policy_context(str(environment_info.get("policy", "")))
        tasks = {str(task["id"]): task for task in payload.get("tasks", [])}
        for simulation in payload.get("simulations", []):
            total_simulations += 1
            if simulation.get("reward_info", {}).get("reward") != 1:
                continue
            successful_simulations += 1
            task_id = str(simulation.get("task_id", ""))
            task = tasks.get(task_id, {})
            goal = _task_goal(task)
            session_id = ":".join(
                (
                    "tau2",
                    result_path.stem,
                    task_id,
                    str(simulation.get("trial", 0)),
                    str(simulation.get("id", "")),
                )
            )
            trajectory_outcomes[session_id] = True
            call_index = 0
            trusted_user_messages: list[str] = []
            untrusted_tool_results: list[str] = []
            for message in simulation.get("messages", []):
                if message.get("role") == "user" and message.get("content"):
                    trusted_user_messages.append(str(message["content"]))
                    continue
                if message.get("role") == "tool" and message.get("content"):
                    untrusted_tool_results.append(str(message["content"])[:1000])
                    continue
                if message.get("role") != "assistant":
                    continue
                for raw_call in message.get("tool_calls") or []:
                    if limit is not None and len(metric_rows) >= limit:
                        stopped = True
                        break
                    call_index += 1
                    tool_name = str(raw_call.get("name", ""))
                    arguments = raw_call.get("arguments", {})
                    if not isinstance(arguments, dict):
                        arguments = {}
                    registration_key = (domain, tool_name)
                    registration = registrations.get(registration_key)
                    spec = definitions.get(registration_key) or _fallback_spec(
                        domain,
                        tool_name,
                        arguments,
                    )
                    if registration is None and mode != "no_guard":
                        registration = (
                            await integrity.register(spec)
                            if effective.integrity_enabled
                            else IntegrityResult(
                                trust_level="integrity_ablation",
                                profile=await profiler.build(spec),
                                sanitized_content=spec.description,
                            )
                        )
                        registrations[registration_key] = registration

                    current_goal = _goal_with_trusted_updates(goal, trusted_user_messages)
                    contract_key = (domain, current_goal)
                    contract = contract_cache.get(contract_key)
                    if contract is None and mode != "no_guard":
                        contract = await contracts.build(
                            current_goal,
                            principal="tau2-agent",
                            entitlements={
                                "actions": [action.value for action in Action],
                                "resources": ["*"],
                                "policy_context": policy_context,
                            },
                        )
                        contract_cache[contract_key] = contract

                    row_started = time.perf_counter()
                    reasons: list[str] = []
                    module = "none"
                    if mode == "no_guard":
                        decision_action = DecisionAction.ALLOW
                    elif effective.integrity_enabled and registration.blocked:
                        decision_action = DecisionAction.DENY
                        reasons = [item.risk_type for item in registration.findings]
                        module = "integrity"
                    else:
                        profile: ToolProfile = registration.profile
                        call = ToolCall(
                            tool_name=tool_name,
                            arguments=arguments,
                            principal="tau2-agent",
                            session_id=session_id,
                            trusted_context="\n".join(trusted_user_messages[-4:])[-4000:],
                            prior_trace="\n".join(untrusted_tool_results[-2:])[-2000:],
                        )
                        if effective.authorization_enabled:
                            decision, effect = await authorization.authorize(
                                call,
                                profile,
                                contract,
                                tool_description=spec.description,
                            )
                            decision_action = decision.action
                            reasons = decision.reasons
                            module = decision.module
                        else:
                            effect = authorization.inferer.infer(profile, call)
                            decision_action = DecisionAction.ALLOW
                            module = "authorization_ablation"
                        if (
                            decision_action == DecisionAction.ALLOW
                            and effective.trajectory_enabled
                        ):
                            state_decision = await trajectory.reserve_call(call, effect, profile)
                            decision_action = state_decision.action
                            reasons = state_decision.reasons
                            module = state_decision.module

                    predicted = (
                        "ALLOW" if decision_action == DecisionAction.ALLOW else "DENY"
                    )
                    if predicted != "ALLOW":
                        trajectory_outcomes[session_id] = False
                    latency_ms = (time.perf_counter() - row_started) * 1000
                    case_id = f"{session_id}:{call_index}"
                    metric_rows.append(
                        MetricRow(
                            case_id=case_id,
                            category=domain,
                            malicious=False,
                            expected="ALLOW",
                            predicted=predicted,
                            latency_ms=latency_ms,
                        )
                    )
                    details.append(
                        {
                            "case_id": case_id,
                            "result_file": result_path.name,
                            "domain": domain,
                            "task_id": task_id,
                            "trial": simulation.get("trial"),
                            "tool": tool_name,
                            "expected": "ALLOW",
                            "predicted": predicted,
                            "decision_action": decision_action.value,
                            "module": module,
                            "reasons": reasons,
                            "latency_ms": latency_ms,
                        }
                    )
                if stopped:
                    break
            if stopped:
                break
        if stopped:
            break

    completed_trajectories = sum(trajectory_outcomes.values())
    evaluated_trajectories = len(trajectory_outcomes)
    report = Tau2Report(
        source=str(root),
        mode=mode,
        metrics=compute_metrics(metric_rows),
        by_domain={
            domain: compute_metrics([row for row in metric_rows if row.category == domain])
            for domain in sorted({row.category for row in metric_rows})
        },
        trajectory_metrics={
            "evaluated_successful_trajectories": evaluated_trajectories,
            "preserved_trajectories": completed_trajectories,
            "blocked_trajectories": evaluated_trajectories - completed_trajectories,
            "trajectory_completion_rate": (
                completed_trajectories / evaluated_trajectories
                if evaluated_trajectories
                else 0.0
            ),
        },
        analysis={
            "published_result_files": len(list(results_root.glob("*.json"))),
            "published_simulations_scanned": total_simulations,
            "reward_one_simulations_scanned": successful_simulations,
            "evaluated_calls": len(metric_rows),
            "selection": "official published trajectories with reward == 1",
            "limit": limit,
            "wall_time_seconds": time.perf_counter() - started_all,
            "llm_available": llm.available,
            "llm_model": effective.llm_model if llm.available else None,
            "llm_client": llm.stats(),
        },
        rows=details,
    )
    await llm.aclose()
    return report


def _load_domain_definitions(domains_root: Path) -> dict[tuple[str, str], ToolSpec]:
    definitions: dict[tuple[str, str], ToolSpec] = {}
    for domain_path in sorted(path for path in domains_root.iterdir() if path.is_dir()):
        for filename in ("tools.py", "user_tools.py"):
            path = domain_path / filename
            if not path.exists():
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                docstring = ast.get_docstring(node)
                if not docstring:
                    continue
                properties = {
                    argument.arg: {"type": _json_type(argument.annotation)}
                    for argument in node.args.args
                    if argument.arg not in {"self", "cls"}
                }
                key = (domain_path.name, node.name)
                definitions[key] = ToolSpec(
                    name=node.name,
                    description=docstring.strip(),
                    input_schema={"type": "object", "properties": properties},
                    namespace=f"tau2:{domain_path.name}",
                    source="tau2-bench",
                    publisher="tau2-bench",
                    trusted=True,
                )
    return definitions


def _compact_policy_context(policy: str, limit: int = 3500) -> str:
    """Retain normative policy clauses without benchmark-label knowledge."""
    selected: list[str] = []
    pattern = re.compile(
        r"\b(?:can|cannot|must|only|allow(?:ed)?|deny|confirm|before|after|should|may)\b",
        flags=re.IGNORECASE,
    )
    for raw_line in policy.splitlines():
        line = raw_line.strip()
        if not line or (not line.startswith("#") and not pattern.search(line)):
            continue
        candidate = "\n".join((*selected, line))
        if len(candidate) > limit:
            break
        selected.append(line)
    return "\n".join(selected)


def _goal_with_trusted_updates(goal: str, user_messages: list[str]) -> str:
    updates = "\n".join(user_messages[-4:])[-4000:]
    if not updates:
        return goal
    return f"{goal}\nAuthenticated user updates:\n{updates}"


def _fallback_spec(domain: str, tool_name: str, arguments: dict[str, Any]) -> ToolSpec:
    return ToolSpec(
        name=tool_name,
        description=f"{tool_name} operation in the {domain} service.",
        input_schema={
            "type": "object",
            "properties": {key: {"type": "string"} for key in arguments},
        },
        namespace=f"tau2:{domain}",
        source="tau2-bench",
        publisher="tau2-bench",
        trusted=True,
    )


def _task_goal(task: dict[str, Any]) -> str:
    instructions = task.get("user_scenario", {}).get("instructions", {})
    return "\n".join(
        value
        for value in (
            str(task.get("ticket") or "").strip(),
            str(instructions.get("reason_for_call") or "").strip(),
            str(instructions.get("known_info") or "").strip(),
        )
        if value
    ) or "Complete the user's requested service task."


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
    return "string"
