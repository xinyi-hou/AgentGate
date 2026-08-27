from __future__ import annotations

from datetime import timedelta

import pytest

from agentgate.capabilities import ToolCapability
from agentgate.detection import DetectionEngine
from agentgate.events import (
    DataType,
    EffectType,
    EventPhase,
    RawToolCall,
    ResourceType,
    SecurityOperation,
    ToolSecurityEvent,
    utc_now,
)
from agentgate.policy import DecisionAction, ResourceAccessRule, load_policy
from agentgate.policy.models import (
    AggregateMetric,
    AggregateRule,
    EventCondition,
    EventRule,
    SecurityPolicy,
    SequenceConstraints,
    SequenceRule,
    SequenceStep,
)
from agentgate.state import SensitiveEventRef, SessionSecurityState


async def test_sensitive_data_exfiltration_requires_real_data_link(runtime_factory) -> None:
    harness = runtime_factory()
    sent: list[str] = []

    async def read(_):
        return {"token": "session-credential-value"}

    async def send(arguments):
        sent.append(arguments["body"])
        return {"sent": True}

    harness.runtime.registry.register(
        ToolCapability(
            tool_name="credential.read",
            possible_operations=[SecurityOperation.READ],
            resource_type=ResourceType.CREDENTIAL,
            sensitive_output_types={DataType.CREDENTIAL},
        ),
        read,
    )
    harness.runtime.registry.register(
        ToolCapability(
            tool_name="message.send",
            possible_operations=[SecurityOperation.SEND],
            resource_type=ResourceType.MESSAGE,
            destination_arg="recipient",
            payload_args=["body"],
            default_effects={EffectType.EXTERNAL},
        ),
        send,
    )
    await harness.runtime.execute(
        RawToolCall(
            tool_name="credential.read",
            principal="ops",
            session_id="exfil",
        )
    )
    unrelated = await harness.runtime.execute(
        RawToolCall(
            tool_name="message.send",
            arguments={"recipient": "outside@example.test", "body": "public status"},
            principal="ops",
            session_id="exfil",
        )
    )
    linked = await harness.runtime.execute(
        RawToolCall(
            tool_name="message.send",
            arguments={
                "recipient": "outside@example.test",
                "body": "session-credential-value",
            },
            principal="ops",
            session_id="exfil",
        )
    )

    assert "sensitive_data_exfiltration" not in unrelated.decision.rule_ids
    assert unrelated.decision.action == DecisionAction.REQUIRE_APPROVAL
    assert linked.decision.action == DecisionAction.BLOCK
    assert "sensitive_data_exfiltration" in linked.decision.rule_ids
    assert not sent


async def test_configured_principal_resource_rule_blocks_unauthorized_access(
    runtime_factory,
) -> None:
    policy = load_policy()
    policy.access_rules = [
        ResourceAccessRule(
            id="contractor_production_files",
            principals=["contractor-*"],
            operations={SecurityOperation.READ, SecurityOperation.WRITE},
            resource_types={ResourceType.FILE},
            resource_patterns=["/production/*"],
            action=DecisionAction.BLOCK,
            reason="Contractors cannot access production files.",
        )
    ]
    harness = runtime_factory(policy)
    executed = False

    async def read(_):
        nonlocal executed
        executed = True
        return {"content": "production"}

    harness.runtime.registry.register(
        ToolCapability(
            tool_name="file.read",
            possible_operations=[SecurityOperation.READ],
            resource_type=ResourceType.FILE,
            resource_arg="path",
        ),
        read,
    )
    outcome = await harness.runtime.execute(
        RawToolCall(
            tool_name="file.read",
            arguments={"path": "/production/config"},
            principal="contractor-7",
            session_id="resource-acl",
        )
    )

    assert outcome.decision.action == DecisionAction.BLOCK
    assert outcome.decision.rule_ids == ["contractor_production_files"]
    assert not executed


async def test_sequence_constraints_require_present_equal_resources() -> None:
    policy = SecurityPolicy(
        sequence_rules=[
            SequenceRule(
                id="same-resource",
                name="Same resource",
                sequence=[
                    SequenceStep(operations={SecurityOperation.READ}),
                    SequenceStep(operations={SecurityOperation.WRITE}),
                ],
                constraints=SequenceConstraints(same_resource=True),
                action=DecisionAction.BLOCK,
                reason="Same resource sequence.",
            )
        ]
    )
    detector = DetectionEngine(policy)
    state = SessionSecurityState(principal="user", session_id="session")
    state.recent_sensitive_events.append(
        SensitiveEventRef(
            call_id="read",
            operation=SecurityOperation.READ,
            resource_type=ResourceType.FILE,
            resource_id=None,
        )
    )
    event = ToolSecurityEvent(
        phase=EventPhase.REQUEST,
        principal="user",
        session_id="session",
        call_id="write",
        tool_name="file.write",
        operation=SecurityOperation.WRITE,
        resource_type=ResourceType.FILE,
        resource_id="/tmp/report",
    )

    decision = await detector.evaluate(event, state)

    assert decision.action == DecisionAction.ALLOW


async def test_detection_rejects_event_state_identity_mismatch() -> None:
    detector = DetectionEngine(SecurityPolicy())
    state = SessionSecurityState(principal="alice", session_id="session-a")
    event = ToolSecurityEvent(
        phase=EventPhase.REQUEST,
        principal="bob",
        session_id="session-b",
        call_id="call",
        tool_name="record.read",
        operation=SecurityOperation.READ,
    )

    with pytest.raises(ValueError, match="identity"):
        await detector.evaluate(event, state)


async def test_declarative_event_condition_action_rule_drives_decision() -> None:
    detector = DetectionEngine(
        SecurityPolicy(
            event_rules=[
                EventRule(
                    id="privileged-execute",
                    name="Privileged execution",
                    condition=EventCondition(
                        operations={SecurityOperation.EXECUTE},
                        effects={EffectType.PRIVILEGED},
                    ),
                    action=DecisionAction.BLOCK,
                    reason="Privileged execution is blocked in this experiment.",
                )
            ]
        )
    )
    state = SessionSecurityState(principal="agent", session_id="eca")
    event = ToolSecurityEvent(
        phase=EventPhase.REQUEST,
        principal="agent",
        session_id="eca",
        call_id="execute",
        tool_name="shell.execute",
        operation=SecurityOperation.EXECUTE,
        effects={EffectType.PRIVILEGED},
    )

    decision = await detector.evaluate(event, state)

    assert decision.action == DecisionAction.BLOCK
    assert decision.rule_ids == ["privileged-execute"]


async def test_aggregate_rule_counts_only_events_inside_event_time_window() -> None:
    detector = DetectionEngine(
        SecurityPolicy(
            aggregate_rules=[
                AggregateRule(
                    id="read-window",
                    name="Read window",
                    condition=EventCondition(
                        operations={SecurityOperation.READ},
                        data_types={DataType.PERSONAL},
                    ),
                    metric=AggregateMetric.AFFECTED_COUNT,
                    threshold=100,
                    window_seconds=60,
                    action=DecisionAction.BLOCK,
                    reason="Read window exceeded.",
                )
            ]
        )
    )
    now = utc_now()
    state = SessionSecurityState(principal="agent", session_id="window")
    state.recent_sensitive_events.extend(
        [
            SensitiveEventRef(
                call_id="expired",
                operation=SecurityOperation.READ,
                data_types={DataType.PERSONAL},
                affected_count=80,
                timestamp=now - timedelta(seconds=61),
            ),
            SensitiveEventRef(
                call_id="current-window",
                operation=SecurityOperation.READ,
                data_types={DataType.PERSONAL},
                affected_count=50,
                timestamp=now - timedelta(seconds=30),
            ),
        ]
    )
    event = ToolSecurityEvent(
        phase=EventPhase.REQUEST,
        principal="agent",
        session_id="window",
        call_id="next-read",
        tool_name="customer.read",
        operation=SecurityOperation.READ,
        data_types={DataType.PERSONAL},
        scope={"argument": "limit", "count": 51},
        timestamp=now,
    )

    decision = await detector.evaluate(event, state)

    assert decision.action == DecisionAction.BLOCK
    assert "projected affected_count=101" in decision.reasons[0].lower()


def test_detection_rules_cannot_override_controls_with_allow_or_restrict() -> None:
    for action in (DecisionAction.ALLOW, DecisionAction.RESTRICT):
        with pytest.raises(ValueError, match="cannot allow"):
            EventRule(
                id="invalid",
                name="Invalid override",
                condition=EventCondition(),
                action=action,
                reason="Invalid.",
            )


async def test_credential_acquisition_and_use_is_detected(runtime_factory) -> None:
    harness = runtime_factory()

    async def read(_):
        return {"credential": "deploy-credential"}

    async def authenticate(_):
        return {"authenticated": True}

    harness.runtime.registry.register(
        ToolCapability(
            tool_name="credential.read",
            possible_operations=[SecurityOperation.READ],
            resource_type=ResourceType.CREDENTIAL,
            sensitive_output_types={DataType.CREDENTIAL},
        ),
        read,
    )
    harness.runtime.registry.register(
        ToolCapability(
            tool_name="identity.authenticate",
            possible_operations=[SecurityOperation.AUTH],
            resource_type=ResourceType.CREDENTIAL,
            resource_arg="account",
            sensitive_input_types={DataType.CREDENTIAL},
            default_effects={EffectType.PRIVILEGED},
        ),
        authenticate,
    )
    await harness.runtime.execute(
        RawToolCall(
            tool_name="credential.read",
            principal="ops",
            session_id="credential-use",
        )
    )
    outcome = await harness.runtime.execute(
        RawToolCall(
            tool_name="identity.authenticate",
            arguments={"account": "prod", "credential": "deploy-credential"},
            principal="ops",
            session_id="credential-use",
        )
    )

    assert outcome.decision.action == DecisionAction.REQUIRE_APPROVAL
    assert "credential_acquisition_and_use" in outcome.decision.rule_ids


async def test_external_download_write_execute_tracks_propagated_object(runtime_factory) -> None:
    harness = runtime_factory()
    executed = False

    async def download(_):
        return {"content": "echo downloaded-script"}

    async def write(_):
        return {"path": "/tmp/downloaded.sh", "written": True}

    async def execute(_):
        nonlocal executed
        executed = True
        return {"exit_code": 0}

    harness.runtime.registry.register(
        ToolCapability(
            tool_name="network.download",
            possible_operations=[SecurityOperation.READ],
            resource_type=ResourceType.NETWORK,
            resource_arg="url",
            destination_arg="url",
            untrusted_output=True,
        ),
        download,
    )
    harness.runtime.registry.register(
        ToolCapability(
            tool_name="file.write",
            possible_operations=[SecurityOperation.WRITE],
            resource_type=ResourceType.FILE,
            resource_arg="path",
            payload_args=["content"],
            default_effects={EffectType.PERSISTENT},
        ),
        write,
    )
    harness.runtime.registry.register(
        ToolCapability(
            tool_name="shell.execute_file",
            possible_operations=[SecurityOperation.EXECUTE],
            resource_type=ResourceType.PROCESS,
            resource_arg="path",
            default_effects={EffectType.PRIVILEGED},
        ),
        execute,
    )
    await harness.runtime.execute(
        RawToolCall(
            tool_name="network.download",
            arguments={"url": "https://unknown.test/tool.sh"},
            principal="developer",
            session_id="download-execute",
        )
    )
    await harness.runtime.execute(
        RawToolCall(
            tool_name="file.write",
            arguments={"path": "/tmp/downloaded.sh", "content": "echo downloaded-script"},
            principal="developer",
            session_id="download-execute",
        )
    )
    outcome = await harness.runtime.execute(
        RawToolCall(
            tool_name="shell.execute_file",
            arguments={"path": "/tmp/downloaded.sh"},
            principal="developer",
            session_id="download-execute",
        )
    )

    assert outcome.decision.action == DecisionAction.BLOCK
    assert "external_download_write_execute" in outcome.decision.rule_ids
    assert not executed


async def test_untrusted_context_then_high_risk_action_requires_approval(runtime_factory) -> None:
    harness = runtime_factory()

    async def read(_):
        return {"content": "external instructions"}

    async def execute(_):
        return {"exit_code": 0}

    harness.runtime.registry.register(
        ToolCapability(
            tool_name="web.read",
            possible_operations=[SecurityOperation.READ],
            resource_type=ResourceType.NETWORK,
            destination_arg="url",
            untrusted_output=True,
        ),
        read,
    )
    harness.runtime.registry.register(
        ToolCapability(
            tool_name="shell.safe_execute",
            possible_operations=[SecurityOperation.EXECUTE],
            resource_type=ResourceType.PROCESS,
        ),
        execute,
    )
    await harness.runtime.execute(
        RawToolCall(
            tool_name="web.read",
            arguments={"url": "https://outside.test/page"},
            principal="agent",
            session_id="untrusted",
        )
    )
    outcome = await harness.runtime.execute(
        RawToolCall(
            tool_name="shell.safe_execute",
            arguments={"command": "echo safe"},
            principal="agent",
            session_id="untrusted",
        )
    )
    assert outcome.decision.action == DecisionAction.REQUIRE_APPROVAL
    assert "untrusted_context_high_risk" in outcome.decision.rule_ids


async def test_cumulative_sensitive_reads_are_blocked_before_threshold_is_crossed(
    runtime_factory,
) -> None:
    harness = runtime_factory()
    executions = 0

    async def read(arguments):
        nonlocal executions
        executions += 1
        return [{"email": f"person-{index}@example.test"} for index in range(arguments["limit"])]

    harness.runtime.registry.register(
        ToolCapability(
            tool_name="customer.read_many",
            possible_operations=[SecurityOperation.READ],
            resource_type=ResourceType.DATABASE,
            scope_arg="limit",
            sensitive_output_types={DataType.PERSONAL},
        ),
        read,
    )
    first = await harness.runtime.execute(
        RawToolCall(
            tool_name="customer.read_many",
            arguments={"limit": 60},
            principal="analyst",
            session_id="cumulative",
        )
    )
    second = await harness.runtime.execute(
        RawToolCall(
            tool_name="customer.read_many",
            arguments={"limit": 60},
            principal="analyst",
            session_id="cumulative",
        )
    )

    assert first.decision.action == DecisionAction.ALLOW
    assert second.decision.action == DecisionAction.BLOCK
    assert "cumulative_sensitive_read_limit" in second.decision.rule_ids
    assert executions == 1
