from __future__ import annotations

import asyncio
import fnmatch
import json
import re

from agentgate.models import (
    Action,
    CallEffect,
    Decision,
    DecisionAction,
    TaskContract,
    ToolCall,
    ToolProfile,
)
from agentgate.modules.authorization.effects import EffectInferer
from agentgate.modules.authorization.rewriter import least_privilege_rewrite
from agentgate.modules.authorization.semantic_risk import (
    CallRiskAssessment,
    CallSemanticRiskDetector,
)
from agentgate.modules.authorization.task_safety import TaskSafetyDetector
from agentgate.policy import PolicyBackend


class AuthorizationModule:
    def __init__(
        self,
        policy: PolicyBackend,
        inferer: EffectInferer | None = None,
        task_safety: TaskSafetyDetector | None = None,
        semantic_risk: CallSemanticRiskDetector | None = None,
    ):
        self.policy = policy
        self.inferer = inferer or EffectInferer()
        self.task_safety = task_safety or TaskSafetyDetector()
        self.semantic_risk = semantic_risk or CallSemanticRiskDetector()

    async def authorize(
        self,
        call: ToolCall,
        profile: ToolProfile,
        contract: TaskContract,
        tool_description: str = "",
        precomputed_call_risk: CallRiskAssessment | None = None,
    ) -> tuple[Decision, CallEffect]:
        effect = self.inferer.infer(profile, call)
        if precomputed_call_risk is None:
            call_risk, task_assessment = await asyncio.gather(
                self.semantic_risk.assess(
                    call,
                    profile,
                    contract.goal,
                    tool_description=tool_description,
                    authorization_context=str(
                        contract.metadata.get("authorization_context", "")
                    ),
                    trusted_context=call.trusted_context,
                    external_context=call.untrusted_context,
                    prior_trace=call.prior_trace,
                ),
                self.task_safety.assess(contract.goal),
            )
        else:
            call_risk = precomputed_call_risk
            task_assessment = await self.task_safety.assess(contract.goal)
        if not call_risk.safe:
            return (
                Decision(
                    action=DecisionAction.DENY,
                    risk_types=call_risk.categories,
                    reasons=call_risk.categories,
                    evidence={
                        "call_risk": call_risk.model_dump(mode="json"),
                        "effect": effect.model_dump(mode="json"),
                    },
                    module="authorization",
                ),
                effect,
            )
        if not task_assessment.safe:
            return (
                Decision(
                    action=DecisionAction.DENY,
                    risk_types=task_assessment.categories,
                    reasons=task_assessment.categories,
                    evidence={
                        "task_safety": task_assessment.model_dump(mode="json"),
                        "effect": effect.model_dump(mode="json"),
                    },
                    module="authorization",
                ),
                effect,
            )
        task_bound_read = _task_bound_preparatory_read(call, effect, contract, call_risk)
        semantic_action = _semantic_action_match(effect, contract, call_risk)
        checks = {
            "identity": call.principal == contract.principal,
            "action": _action_matches(effect, contract) or task_bound_read or semantic_action,
            "resource": _resource_matches(effect.resource, contract.allowed_resources)
            or _semantic_resource_match(call_risk, contract),
            "scope": _scope_matches(effect, profile, contract),
            "effect": _effects_match(effect, contract)
            or (task_bound_read and effect.effects <= {"data_read"})
            or _semantic_effect_match(effect, contract, call_risk),
            "destination": _destination_matches(effect, contract),
        }
        requires_approval = effect.action in {Action.DELETE, Action.EXECUTE} or bool(
            effect.effects & {"destructive", "financial_transaction", "credential_creation"}
        )
        policy_input = {
            "checks": checks,
            "requires_approval": requires_approval,
            "approval_valid": bool(call.approval_token)
            and call.approval_token in contract.approval_tokens,
            "requires_confirmation": profile.requires_confirmation and not requires_approval,
            "confirmed": effect.action in contract.confirmed_actions,
            "effect": effect.model_dump(mode="json"),
            "contract": contract.model_dump(mode="json"),
        }
        result = await self.policy.decide(policy_input)
        action = DecisionAction(str(result.get("action", DecisionAction.DENY)))
        reasons = list(result.get("reasons", []))

        rewrite = None
        rewriteable_mismatches = set(name for name, matched in checks.items() if not matched) <= {
            "scope",
            "resource",
            "effect",
        }
        rewriteable_effects = (effect.effects - contract.allowed_effects) <= {"data_export"}
        if action == DecisionAction.DENY and rewriteable_mismatches and rewriteable_effects:
            rewrite = least_privilege_rewrite(call, effect, contract)
            if rewrite is not None:
                action = DecisionAction.LIMIT_SCOPE
                reasons = ["least_privilege_rewrite"]

        return (
            Decision(
                action=action,
                risk_types=[reason for reason in reasons],
                reasons=reasons,
                confidence=min(call_risk.confidence, task_assessment.confidence),
                rewritten_arguments=rewrite,
                evidence={
                    "checks": checks,
                    "effect": effect.model_dump(mode="json"),
                    "call_risk": call_risk.model_dump(mode="json"),
                    "task_safety": task_assessment.model_dump(mode="json"),
                },
                module="authorization",
            ),
            effect,
        )


def _resource_matches(actual: str, allowed: set[str]) -> bool:
    if "*" in allowed:
        return True
    aliases = {actual}
    if ":" in actual:
        kind, _ = actual.split(":", 1)
        aliases.add(kind)
        aliases.add(f"{kind}:*")
        if kind == "order":
            aliases.add("orders")
        if kind == "account":
            aliases.add("customers")
    return any(
        fnmatch.fnmatchcase(candidate, pattern) for candidate in aliases for pattern in allowed
    )


def _semantic_resource_match(
    call_risk: CallRiskAssessment,
    contract: TaskContract,
) -> bool:
    return bool(
        contract.metadata.get("resource_catalog_open")
        and contract.metadata.get("task_resource_open")
        and call_risk.safe
        and call_risk.semantic_signals is not None
        and call_risk.semantic_signals.resource_alignment == "aligned"
    )


def _effects_match(effect: CallEffect, contract: TaskContract) -> bool:
    safe_internal = {"internal_notification", "human_escalation"}
    relevant_effects = effect.effects - safe_internal
    if relevant_effects & contract.forbidden_effects:
        return False
    return relevant_effects <= contract.allowed_effects or not relevant_effects


def _action_matches(effect: CallEffect, contract: TaskContract) -> bool:
    if effect.action in contract.allowed_actions:
        return True
    if "human_escalation" in effect.effects and effect.destination == "internal":
        return True
    return (
        effect.action == Action.TRANSMIT
        and effect.destination == "internal"
        and "internal_notification" in effect.effects
        and Action.WRITE in contract.allowed_actions
    )


def _semantic_action_match(
    effect: CallEffect,
    contract: TaskContract,
    call_risk: CallRiskAssessment,
) -> bool:
    ceiling = set(contract.metadata.get("action_ceiling", []))
    signals = call_risk.semantic_signals
    return bool(
        call_risk.safe
        and signals is not None
        and effect.action.value in ceiling
        and signals.goal_alignment == "aligned"
        and signals.action_alignment == "aligned"
        and signals.effect_alignment == "aligned"
    )


def _semantic_effect_match(
    effect: CallEffect,
    contract: TaskContract,
    call_risk: CallRiskAssessment,
) -> bool:
    relevant_effects = effect.effects - {"internal_notification", "human_escalation"}
    ceiling = set(contract.metadata.get("effect_ceiling", []))
    signals = call_risk.semantic_signals
    return bool(
        call_risk.safe
        and signals is not None
        and relevant_effects <= ceiling
        and signals.goal_alignment == "aligned"
        and signals.effect_alignment == "aligned"
    )


def _scope_matches(
    effect: CallEffect,
    profile: ToolProfile,
    contract: TaskContract,
) -> bool:
    if effect.record_count <= contract.max_records:
        return True
    return (
        effect.action == Action.READ
        and effect.destination in {"agent_context", "internal"}
        and not profile.output_sensitivity
        and effect.record_count <= 100
    )


def _destination_matches(effect: CallEffect, contract: TaskContract) -> bool:
    if "external_transmission" not in effect.effects:
        return True
    if not contract.external_transmission:
        return False
    return bool(contract.metadata.get("destination_open")) or (
        "*" in contract.allowed_destinations or effect.destination in contract.allowed_destinations
    )


_PREPARATORY_READ_STOPWORDS = {
    "api",
    "detail",
    "details",
    "fetch",
    "find",
    "get",
    "info",
    "information",
    "list",
    "lookup",
    "query",
    "read",
    "retrieve",
    "search",
    "service",
    "tool",
}


def _task_bound_preparatory_read(
    call: ToolCall,
    effect: CallEffect,
    contract: TaskContract,
    call_risk: CallRiskAssessment,
) -> bool:
    if effect.action != Action.READ or not contract.metadata.get("read_entitled", False):
        return False
    if call_risk.semantic_signals is not None and all(
        getattr(call_risk.semantic_signals, field) == "aligned"
        for field in ("goal_alignment", "resource_alignment", "effect_alignment")
    ):
        return True

    task = _normalize_phrase(contract.goal)
    for value in _scalar_values(call.arguments):
        normalized = _normalize_phrase(value)
        if len(normalized) >= 3 and normalized in task:
            return True
    resource_value = effect.resource.split(":", 1)[-1]
    normalized_resource = _normalize_phrase(resource_value)
    if len(normalized_resource) >= 3 and normalized_resource not in {"unknown", "*"}:
        if normalized_resource in task:
            return True

    tool_terms = _normalized_terms(call.tool_name) - _PREPARATORY_READ_STOPWORDS
    task_terms = set(task.split())
    return bool({term for term in tool_terms if len(term) >= 4} & task_terms)


def _scalar_values(value: object) -> list[str]:
    if isinstance(value, dict):
        return [item for nested in value.values() for item in _scalar_values(nested)]
    if isinstance(value, (list, tuple, set)):
        return [item for nested in value for item in _scalar_values(nested)]
    if value is None or isinstance(value, bool):
        return []
    return [str(value)]


def _normalize_phrase(value: object) -> str:
    rendered = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", str(value))
    return re.sub(r"[^a-z0-9]+", " ", rendered.lower()).strip()


def _normalized_terms(value: object) -> set[str]:
    if isinstance(value, str):
        normalized = _normalize_phrase(value)
    else:
        normalized = _normalize_phrase(json.dumps(value, sort_keys=True, default=str))
    return set(normalized.split())
