from __future__ import annotations

import fnmatch

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
from agentgate.modules.authorization.semantic_risk import CallSemanticRiskDetector
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
        self, call: ToolCall, profile: ToolProfile, contract: TaskContract
    ) -> tuple[Decision, CallEffect]:
        effect = self.inferer.infer(profile, call)
        call_risk = await self.semantic_risk.assess(call, profile, contract.goal)
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
        task_assessment = await self.task_safety.assess(contract.goal)
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
        checks = {
            "identity": call.principal == contract.principal,
            "action": effect.action in contract.allowed_actions,
            "resource": _resource_matches(effect.resource, contract.allowed_resources),
            "scope": effect.record_count <= contract.max_records,
            "effect": _effects_match(effect, contract),
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
                rewritten_arguments=rewrite,
                evidence={"checks": checks, "effect": effect.model_dump(mode="json")},
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
        fnmatch.fnmatchcase(candidate, pattern)
        for candidate in aliases
        for pattern in allowed
    )


def _effects_match(effect: CallEffect, contract: TaskContract) -> bool:
    if effect.effects & contract.forbidden_effects:
        return False
    return effect.effects <= contract.allowed_effects or not effect.effects


def _destination_matches(effect: CallEffect, contract: TaskContract) -> bool:
    if "external_transmission" not in effect.effects:
        return True
    if not contract.external_transmission:
        return False
    return not contract.allowed_destinations or effect.destination in contract.allowed_destinations
