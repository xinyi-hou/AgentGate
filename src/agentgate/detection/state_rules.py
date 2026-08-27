from __future__ import annotations

from datetime import timedelta

from agentgate.detection.conditions import event_matches
from agentgate.events.models import ToolSecurityEvent
from agentgate.policy.models import (
    AggregateMetric,
    AggregateRule,
    SecurityDecision,
    StateRule,
)
from agentgate.state.models import SensitiveEventRef, SessionSecurityState


class StateRuleDetector:
    """Evaluates flowbit-style state predicates and SIEM-style window aggregates."""

    def __init__(
        self,
        state_rules: list[StateRule],
        aggregate_rules: list[AggregateRule],
    ):
        self.state_rules = state_rules
        self.aggregate_rules = aggregate_rules

    def evaluate(
        self,
        event: ToolSecurityEvent,
        state: SessionSecurityState,
    ) -> list[SecurityDecision]:
        decisions = self._state_decisions(event, state)
        decisions.extend(self._aggregate_decisions(event, state))
        return decisions

    def _state_decisions(
        self,
        event: ToolSecurityEvent,
        state: SessionSecurityState,
    ) -> list[SecurityDecision]:
        return [
            SecurityDecision(
                action=rule.action,
                rule_ids=[rule.id],
                reasons=[rule.reason],
                severity=rule.severity,
            )
            for rule in self.state_rules
            if rule.required_labels.issubset(state.labels)
            and not bool(rule.forbidden_labels & state.labels)
            and event_matches(event, rule.condition)
        ]

    def _aggregate_decisions(
        self,
        event: ToolSecurityEvent,
        state: SessionSecurityState,
    ) -> list[SecurityDecision]:
        decisions: list[SecurityDecision] = []
        for rule in self.aggregate_rules:
            if not event_matches(event, rule.condition):
                continue
            projected = _window_value(rule, event, state.recent_sensitive_events)
            if projected <= rule.threshold:
                continue
            decisions.append(
                SecurityDecision(
                    action=rule.action,
                    rule_ids=[rule.id],
                    reasons=[
                        f"{rule.reason} Projected {rule.metric.value.lower()}={projected} "
                        f"within {rule.window_seconds}s exceeds {rule.threshold}."
                    ],
                    severity=rule.severity,
                )
            )
        return decisions


def _window_value(
    rule: AggregateRule,
    current: ToolSecurityEvent,
    history: list[SensitiveEventRef],
) -> int:
    start = current.timestamp - timedelta(seconds=rule.window_seconds)
    matched = [
        item
        for item in history
        if start <= item.timestamp <= current.timestamp and event_matches(item, rule.condition)
    ]
    if rule.metric == AggregateMetric.EVENT_COUNT:
        return len(matched) + 1
    previous = sum(max(1, item.affected_count) for item in matched)
    requested = int((current.scope or {}).get("count", current.affected_count or 1))
    return previous + max(1, requested)
