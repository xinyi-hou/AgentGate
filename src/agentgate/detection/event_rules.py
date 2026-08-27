from __future__ import annotations

from agentgate.detection.conditions import event_matches
from agentgate.events.models import ToolSecurityEvent
from agentgate.policy.models import EventRule, SecurityDecision


class EventRuleEngine:
    """Falco-style event-condition-action evaluation for one normalized event."""

    def __init__(self, rules: list[EventRule]):
        self.rules = rules

    def evaluate(self, event: ToolSecurityEvent) -> list[SecurityDecision]:
        return [
            SecurityDecision(
                action=rule.action,
                rule_ids=[rule.id],
                reasons=[rule.reason],
                severity=rule.severity,
            )
            for rule in self.rules
            if event_matches(event, rule.condition)
        ]
