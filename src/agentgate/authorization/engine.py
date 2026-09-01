from __future__ import annotations

from fnmatch import fnmatch
from urllib.parse import urlparse

from agentgate.authorization.models import TaskAuthorization
from agentgate.events.models import SecurityOperation, ToolSecurityEvent
from agentgate.policy.models import DecisionAction, SecurityDecision, Severity


class TaskAuthorizer:
    def evaluate(
        self,
        event: ToolSecurityEvent,
        authorization: TaskAuthorization,
    ) -> SecurityDecision:
        violations: list[str] = []
        if event.principal != authorization.principal:
            violations.append("principal")
        if event.task_id != authorization.task_id:
            violations.append("task_id")
        # UNKNOWN remains approval-gated by the global semantic policy. Treating it as an
        # irrevocable authorization mismatch would make a bound one-time approval unusable.
        if (
            event.operation != SecurityOperation.UNKNOWN
            and event.operation not in authorization.allowed_operations
        ):
            violations.append("operation")
        resource = event.resource_id or ""
        if resource and not any(
            _resource_matches(resource, pattern)
            for pattern in authorization.allowed_resource_patterns
        ):
            violations.append("resource")
        if (
            event.effects - authorization.allowed_effects
            or event.effects & authorization.forbidden_effects
        ):
            violations.append("effect")
        if event.destination and not any(
            _destination_matches(event.destination, allowed)
            for allowed in authorization.allowed_destinations
        ):
            violations.append("destination")

        requested = int((event.scope or {}).get("count", 1))
        if authorization.max_records is not None and requested > authorization.max_records:
            argument = (event.scope or {}).get("argument")
            if not violations and argument:
                rewritten = dict(event.arguments or {})
                rewritten[str(argument)] = authorization.max_records
                return SecurityDecision(
                    action=DecisionAction.RESTRICT,
                    rule_ids=["task_authorization_scope"],
                    reasons=[
                        "Task authorization limits the call to "
                        f"{authorization.max_records} records."
                    ],
                    rewritten_arguments=rewritten,
                    severity=Severity.MEDIUM,
                )
            violations.append("scope")

        if violations:
            return SecurityDecision(
                action=DecisionAction.BLOCK,
                rule_ids=[f"task_authorization_{item}" for item in violations],
                reasons=[f"Task authorization mismatch: {', '.join(violations)}."],
                severity=Severity.HIGH,
            )
        return SecurityDecision(action=DecisionAction.ALLOW)


def _resource_matches(resource: str, pattern: str) -> bool:
    if pattern == "*" or fnmatch(resource, pattern):
        return True
    _, separator, identifier = pattern.partition(":")
    return bool(separator and identifier and fnmatch(resource, identifier))


def _destination_matches(actual: str, allowed: str) -> bool:
    if actual.casefold() == allowed.casefold():
        return True

    def host(value: str) -> str:
        rendered = value.rstrip(".,;:!?")
        if "@" in rendered and "://" not in rendered:
            return rendered.casefold()
        parsed = urlparse(rendered if "://" in rendered else f"//{rendered}")
        return (parsed.hostname or rendered.split("/", 1)[0]).casefold()

    return host(actual) == host(allowed)
