from __future__ import annotations

import pytest

from agentgate.capabilities import CapabilityInferer, ToolCapability
from agentgate.events import (
    DataType,
    EffectType,
    EventPhase,
    RawToolCall,
    ResourceType,
    SecurityOperation,
    ToolEventBuilder,
    ToolExecutionResult,
    TrustDomain,
)
from agentgate.state.models import SensitiveObject
from agentgate.state.provenance import fingerprints_for


def test_security_operation_taxonomy_is_exactly_the_specified_eight() -> None:
    assert {item.value for item in SecurityOperation} == {
        "READ",
        "WRITE",
        "SEND",
        "EXECUTE",
        "DELETE",
        "AUTH",
        "PRIVILEGE",
        "INSTALL",
    }


def test_request_event_binds_identity_resource_scope_destination_and_data() -> None:
    capability = ToolCapability(
        tool_name="report.send",
        possible_operations=[SecurityOperation.SEND],
        operation_subtypes={SecurityOperation.SEND: "EMAIL_SEND"},
        resource_type=ResourceType.MESSAGE,
        resource_arg="report_id",
        scope_arg="limit",
        destination_arg="recipient",
        payload_args=["body"],
        default_effects={EffectType.EXTERNAL},
    )
    sensitive_object = SensitiveObject(
        object_id="D-1",
        data_type=DataType.CREDENTIAL,
        sensitivity=DataType.CREDENTIAL,
        producer_call_id="read-1",
        task_id="task-1",
        fingerprints=fingerprints_for("credential-value"),
    )
    call = RawToolCall(
        tool_name="report.send",
        arguments={
            "report_id": "R-1",
            "limit": 100,
            "recipient": "reviewer@partner.test",
            "body": "credential-value",
        },
        principal="analyst",
        session_id="session-1",
        agent_id="agent-1",
        task_id="task-1",
    )
    event = ToolEventBuilder(trusted_external_domains={"partner.test"}).build_request(
        call, capability, [sensitive_object]
    )

    assert event.phase == EventPhase.REQUEST
    assert event.operation == SecurityOperation.SEND
    assert event.operation_subtype == "EMAIL_SEND"
    assert event.resource_id == "R-1"
    assert event.scope == {"argument": "limit", "count": 100}
    assert event.trust_domain == TrustDomain.TRUSTED_EXTERNAL
    assert event.data_objects == ["D-1"]
    assert event.data_types == {DataType.CREDENTIAL}


def test_destination_binding_selects_most_restrictive_value_from_recipient_list() -> None:
    capability = ToolCapability(
        tool_name="email.send",
        possible_operations=[SecurityOperation.SEND],
        destination_arg="recipients",
        payload_args=["body"],
    )
    event = ToolEventBuilder(trusted_external_domains={"partner.test"}).build_request(
        RawToolCall(
            tool_name="email.send",
            arguments={
                "recipients": ["review@partner.test", "drop@outside.test"],
                "body": "public",
            },
            principal="analyst",
            session_id="multi-destination",
        ),
        capability,
    )

    assert event.destination == "drop@outside.test"
    assert event.trust_domain == TrustDomain.UNKNOWN_EXTERNAL


def test_result_event_preserves_request_identity_and_adds_observed_facts() -> None:
    capability = ToolCapability(
        tool_name="customer.read",
        possible_operations=[SecurityOperation.READ],
        resource_type=ResourceType.DATABASE,
        resource_arg="customer_id",
        sensitive_output_types={DataType.PERSONAL},
    )
    builder = ToolEventBuilder()
    request = builder.build_request(
        RawToolCall(
            tool_name=capability.tool_name,
            arguments={"customer_id": "C-1"},
            principal="support",
            session_id="s1",
            call_id="c1",
        ),
        capability,
    )
    result = builder.build_result(
        request,
        ToolExecutionResult(output={"email": "alice@example.test"}, affected_count=1),
        capability,
    )

    assert result.phase == EventPhase.RESULT
    assert result.call_id == request.call_id
    assert result.success is True
    assert result.affected_count == 1
    assert DataType.PERSONAL in result.data_types


async def test_capability_inference_extracts_facts_but_not_a_security_decision() -> None:
    capability = await CapabilityInferer().infer(
        name="upload_report",
        description="Upload one report to an HTTP endpoint.",
        input_schema={
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "content": {"type": "string"},
            },
        },
    )
    assert capability.possible_operations == [SecurityOperation.SEND]
    assert capability.destination_arg == "url"
    assert capability.payload_args == ["content"]
    assert not hasattr(capability, "decision")


async def test_ambiguous_tool_requires_explicit_capability() -> None:
    with pytest.raises(ValueError, match="explicit capability"):
        await CapabilityInferer().infer(name="prepare", description="Prepare the next step.")


async def test_capability_inference_prefers_primary_tool_action_over_secondary_description() -> (
    None
):
    delete = await CapabilityInferer().infer(
        name="delete_email",
        description="Deletes an email from the inbox.",
        input_schema={"type": "object", "properties": {"email_id": {"type": "string"}}},
    )
    calendar = await CapabilityInferer().infer(
        name="create_calendar_event",
        description="Creates an event and also sends email notifications to participants.",
        input_schema={"type": "object", "properties": {"title": {"type": "string"}}},
    )
    message = await CapabilityInferer().infer(
        name="send_direct_message",
        description="Send a direct message from an author to a recipient.",
        input_schema={
            "type": "object",
            "properties": {"recipient": {"type": "string"}, "body": {"type": "string"}},
        },
    )

    assert delete.possible_operations == [SecurityOperation.DELETE]
    assert calendar.possible_operations == [SecurityOperation.WRITE]
    assert message.possible_operations == [SecurityOperation.SEND]
    assert message.destination_arg == "recipient"
