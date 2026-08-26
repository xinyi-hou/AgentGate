from __future__ import annotations

import re
from fnmatch import fnmatch
from typing import Any

from agentgate.events.models import SecurityOperation, ToolSecurityEvent, TrustDomain
from agentgate.policy.models import (
    DecisionAction,
    ResourceAccessRule,
    SecurityDecision,
    Severity,
    SingleCallPolicy,
)
from agentgate.state.models import SessionSecurityState


class SingleCallDetector:
    def __init__(
        self,
        policy: SingleCallPolicy,
        access_rules: list[ResourceAccessRule] | None = None,
    ):
        self.policy = policy
        self.access_rules = access_rules or []

    def evaluate(
        self,
        event: ToolSecurityEvent,
        state: SessionSecurityState,
    ) -> SecurityDecision:
        if state.isolated:
            return SecurityDecision(
                action=DecisionAction.BLOCK,
                rule_ids=["session_isolated"],
                reasons=["The session is isolated."],
                severity=Severity.CRITICAL,
            )
        decisions: list[SecurityDecision] = []
        dangerous_command = self._dangerous_command(event)
        if dangerous_command is not None:
            decisions.append(dangerous_command)
        if (
            event.operation == SecurityOperation.DELETE
            and event.resource_id in self.policy.dangerous_delete_resources
        ):
            decisions.append(
                SecurityDecision(
                    action=DecisionAction.BLOCK,
                    rule_ids=["dangerous_delete"],
                    reasons=["The call targets a protected root resource."],
                    severity=Severity.CRITICAL,
                )
            )

        access = self._access_control(event)
        if access is not None:
            decisions.append(access)

        restriction = self._scope_restriction(event)
        if restriction is not None:
            decisions.append(restriction)
        if (
            event.operation == SecurityOperation.SEND
            and event.trust_domain == TrustDomain.UNKNOWN_EXTERNAL
        ):
            decisions.append(
                SecurityDecision(
                    action=self.policy.unknown_external_send_action,
                    rule_ids=["unknown_external_send"],
                    reasons=[
                        "Sending to an unknown external destination requires explicit control."
                    ],
                    severity=Severity.HIGH,
                )
            )
        if event.operation in self.policy.require_approval_operations:
            decisions.append(
                SecurityDecision(
                    action=DecisionAction.REQUIRE_APPROVAL,
                    rule_ids=["high_impact_operation"],
                    reasons=[f"{event.operation.value} requires approval."],
                    severity=Severity.HIGH,
                )
            )
        return merge_single_call_decisions(decisions)

    def _access_control(self, event: ToolSecurityEvent) -> SecurityDecision | None:
        resource_id = event.resource_id or ""
        for rule in self.access_rules:
            if not any(fnmatch(event.principal, pattern) for pattern in rule.principals):
                continue
            if rule.operations and event.operation not in rule.operations:
                continue
            if rule.resource_types and event.resource_type not in rule.resource_types:
                continue
            if not any(fnmatch(resource_id, pattern) for pattern in rule.resource_patterns):
                continue
            return SecurityDecision(
                action=rule.action,
                rule_ids=[rule.id],
                reasons=[rule.reason],
                severity=rule.severity,
            )
        return None

    def _dangerous_command(self, event: ToolSecurityEvent) -> SecurityDecision | None:
        if event.operation != SecurityOperation.EXECUTE:
            return None
        commands = command_values(event.arguments or {}, self.policy.command_argument_names)
        if not any(
            re.search(pattern, command, flags=re.IGNORECASE)
            for pattern in self.policy.dangerous_command_patterns
            for command in commands
        ):
            return None
        return SecurityDecision(
            action=DecisionAction.BLOCK,
            rule_ids=["dangerous_command"],
            reasons=["The command matches a destructive execution policy."],
            severity=Severity.CRITICAL,
        )

    def _scope_restriction(self, event: ToolSecurityEvent) -> SecurityDecision | None:
        max_scope = self.policy.max_scope.get(event.operation)
        requested = int((event.scope or {}).get("count", 0))
        if max_scope is None or requested <= max_scope:
            return None
        argument = (event.scope or {}).get("argument")
        rewritten = dict(event.arguments or {})
        if argument:
            rewritten[str(argument)] = max_scope
        return SecurityDecision(
            action=DecisionAction.RESTRICT,
            rule_ids=["scope_limit"],
            reasons=[f"The requested scope is limited to {max_scope}."],
            rewritten_arguments=rewritten,
            severity=Severity.MEDIUM,
        )


def command_values(value: Any, names: set[str]) -> list[str]:
    output: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in names:
                output.append(str(item))
            output.extend(command_values(item, names))
    elif isinstance(value, (list, tuple)):
        for item in value:
            output.extend(command_values(item, names))
    return output


def merge_single_call_decisions(decisions: list[SecurityDecision]) -> SecurityDecision:
    if not decisions:
        return SecurityDecision(action=DecisionAction.ALLOW)
    precedence = {
        DecisionAction.ALLOW: 0,
        DecisionAction.AUDIT: 10,
        DecisionAction.RESTRICT: 20,
        DecisionAction.REQUIRE_APPROVAL: 30,
        DecisionAction.BLOCK: 40,
        DecisionAction.ISOLATE: 50,
    }
    selected = max(decisions, key=lambda item: precedence[item.action])
    severity_order = list(Severity)
    severities = [item.severity for item in decisions if item.severity is not None]
    return selected.model_copy(
        update={
            "rule_ids": [rule for item in decisions for rule in item.rule_ids],
            "reasons": [reason for item in decisions for reason in item.reasons],
            "rewritten_arguments": next(
                (
                    item.rewritten_arguments
                    for item in decisions
                    if item.rewritten_arguments is not None
                ),
                None,
            ),
            "severity": max(severities, key=severity_order.index) if severities else None,
        }
    )
