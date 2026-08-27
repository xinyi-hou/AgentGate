from __future__ import annotations

from agentgate.detection.sequence_engine import SequenceEngine
from agentgate.detection.single_call import SingleCallDetector
from agentgate.detection.state_rules import StateRuleDetector
from agentgate.events.models import ToolSecurityEvent
from agentgate.policy.models import (
    DecisionAction,
    SecurityDecision,
    SecurityPolicy,
    Severity,
)
from agentgate.state.models import SessionSecurityState

_PRECEDENCE = {
    DecisionAction.ALLOW: 0,
    DecisionAction.AUDIT: 10,
    DecisionAction.RESTRICT: 20,
    DecisionAction.REQUIRE_APPROVAL: 30,
    DecisionAction.BLOCK: 40,
}


class DetectionEngine:
    def __init__(self, policy: SecurityPolicy):
        self.policy = policy
        self.single_call = SingleCallDetector(
            policy.single_call,
            policy.event_rules,
            policy.access_rules,
        )
        self.state_rules = StateRuleDetector(policy.state_rules, policy.aggregate_rules)
        self.sequences = SequenceEngine(policy.sequence_rules)

    async def evaluate(
        self,
        event: ToolSecurityEvent,
        state: SessionSecurityState,
    ) -> SecurityDecision:
        if event.principal != state.principal or event.session_id != state.session_id:
            raise ValueError("event identity does not match session state")
        decisions = [self.single_call.evaluate(event, state)]
        decisions.extend(self.state_rules.evaluate(event, state))
        for rule, match in self.sequences.evaluate(event, state):
            decisions.append(
                SecurityDecision(
                    action=rule.action,
                    rule_ids=[rule.id],
                    reasons=[f"{rule.reason} Calls: {', '.join(match.call_ids)}"],
                    severity=rule.severity,
                )
            )
        return merge_decisions(decisions)


def merge_decisions(decisions: list[SecurityDecision]) -> SecurityDecision:
    selected = max(decisions, key=lambda item: _PRECEDENCE[item.action])
    rewritten = next(
        (item.rewritten_arguments for item in decisions if item.rewritten_arguments is not None),
        None,
    )
    severity_order = list(Severity)
    severities = [item.severity for item in decisions if item.severity is not None]
    return selected.model_copy(
        update={
            "rule_ids": list(dict.fromkeys(rule for item in decisions for rule in item.rule_ids)),
            "reasons": list(dict.fromkeys(reason for item in decisions for reason in item.reasons)),
            "rewritten_arguments": rewritten,
            "severity": max(severities, key=severity_order.index) if severities else None,
        }
    )
