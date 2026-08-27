from __future__ import annotations

from fnmatch import fnmatch

from agentgate.authorization.contracts import TaskContract
from agentgate.events.models import ToolSecurityEvent
from agentgate.policy.models import DecisionAction, SecurityDecision, Severity


class TaskAuthorizer:
    def evaluate(
        self,
        event: ToolSecurityEvent,
        contract: TaskContract,
    ) -> SecurityDecision:
        violations: list[str] = []
        if event.principal != contract.principal:
            violations.append("principal")
        if contract.task_id and event.task_id != contract.task_id:
            violations.append("task_id")
        if event.operation not in contract.allowed_operations:
            violations.append("operation")
        resource = event.resource_id or ""
        if resource and not any(
            _resource_matches(resource, pattern)
            for pattern in contract.allowed_resource_patterns
        ):
            violations.append("resource")
        if event.effects - contract.allowed_effects or event.effects & contract.forbidden_effects:
            violations.append("effect")
        if event.destination and event.destination not in contract.allowed_destinations:
            violations.append("destination")

        requested = int((event.scope or {}).get("count", 1))
        if contract.max_records is not None and requested > contract.max_records:
            argument = (event.scope or {}).get("argument")
            if not violations and argument:
                rewritten = dict(event.arguments or {})
                rewritten[str(argument)] = contract.max_records
                return SecurityDecision(
                    action=DecisionAction.RESTRICT,
                    rule_ids=["task_contract_scope"],
                    reasons=[f"Task contract limits the call to {contract.max_records} records."],
                    rewritten_arguments=rewritten,
                    severity=Severity.MEDIUM,
                )
            violations.append("scope")

        if violations:
            return SecurityDecision(
                action=DecisionAction.BLOCK,
                rule_ids=[f"task_contract_{item}" for item in violations],
                reasons=[f"Task contract mismatch: {', '.join(violations)}."],
                severity=Severity.HIGH,
            )
        return SecurityDecision(action=DecisionAction.ALLOW)


def _resource_matches(resource: str, pattern: str) -> bool:
    if pattern == "*" or fnmatch(resource, pattern):
        return True
    _, separator, identifier = pattern.partition(":")
    return bool(separator and identifier and fnmatch(resource, identifier))
