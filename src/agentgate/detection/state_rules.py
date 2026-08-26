from __future__ import annotations

from agentgate.events.models import DataType, SecurityOperation, ToolSecurityEvent, TrustDomain
from agentgate.policy.models import (
    DecisionAction,
    SecurityDecision,
    Severity,
    SingleCallPolicy,
    StatePolicy,
)
from agentgate.state.counters import SENSITIVE_TYPES
from agentgate.state.models import SessionSecurityState, StateLabel


class StateRuleDetector:
    def __init__(self, single_call: SingleCallPolicy, state_policy: StatePolicy):
        self.single_call = single_call
        self.state_policy = state_policy

    def evaluate(
        self,
        event: ToolSecurityEvent,
        state: SessionSecurityState,
    ) -> SecurityDecision:
        if (
            StateLabel.EXPOSED_TO_UNTRUSTED_CONTENT in state.labels
            and event.operation in self.single_call.untrusted_high_risk_operations
            and not event.trusted_context
        ):
            return SecurityDecision(
                action=DecisionAction.REQUIRE_APPROVAL,
                rule_ids=["untrusted_context_high_risk"],
                reasons=["A high-risk operation follows exposure to untrusted content."],
                severity=Severity.HIGH,
            )
        if event.operation == SecurityOperation.READ and event.data_types & SENSITIVE_TYPES:
            projected = state.counters.get("sensitive_records_read", 0) + max(
                1, int((event.scope or {}).get("count", 1))
            )
            if projected > self.state_policy.max_sensitive_records_read:
                return SecurityDecision(
                    action=DecisionAction.BLOCK,
                    rule_ids=["cumulative_sensitive_read_limit"],
                    reasons=["The session cumulative sensitive-read limit would be exceeded."],
                    severity=Severity.HIGH,
                )
        if (
            StateLabel.HAS_CREDENTIAL in state.labels
            and event.operation == SecurityOperation.SEND
            and event.trust_domain == TrustDomain.UNKNOWN_EXTERNAL
            and DataType.CREDENTIAL not in event.data_types
        ):
            return SecurityDecision(
                action=DecisionAction.AUDIT,
                rule_ids=["credential_history_external_send"],
                reasons=["External send follows credential access, but no data link was found."],
                severity=Severity.LOW,
            )
        return SecurityDecision(action=DecisionAction.ALLOW)
