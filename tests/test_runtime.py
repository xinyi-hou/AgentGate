from __future__ import annotations

import json

import pytest

from agentgate.capabilities import ToolCapability
from agentgate.enforcement import apply_restriction
from agentgate.events import (
    DataType,
    EffectType,
    RawToolCall,
    ResourceType,
    SecurityOperation,
)
from agentgate.policy import DecisionAction


async def test_blocked_command_is_not_executed_or_added_to_fact_state(runtime_factory) -> None:
    harness = runtime_factory()
    executed = False

    async def shell(arguments):
        nonlocal executed
        executed = True
        return {"command": arguments["command"]}

    harness.runtime.registry.register(
        ToolCapability(
            tool_name="shell.execute",
            possible_operations=[SecurityOperation.EXECUTE],
            resource_type=ResourceType.PROCESS,
            resource_arg="command",
            default_effects={EffectType.PRIVILEGED},
        ),
        shell,
    )
    outcome = await harness.runtime.execute(
        RawToolCall(
            tool_name="shell.execute",
            arguments={"command": "rm -rf /"},
            principal="ops",
            session_id="blocked",
        )
    )
    state = await harness.runtime.state_manager.get("ops", "blocked")

    assert outcome.decision.action == DecisionAction.BLOCK
    assert "dangerous_command" in outcome.decision.rule_ids
    assert not executed
    assert not state.recent_sensitive_events
    assert state.counters["execute_count"] == 0


async def test_restriction_only_reduces_scope_and_rechecks_before_execution(
    runtime_factory,
) -> None:
    harness = runtime_factory()
    received = None

    async def read(arguments):
        nonlocal received
        received = dict(arguments)
        return [{"id": index} for index in range(arguments["limit"])]

    harness.runtime.registry.register(
        ToolCapability(
            tool_name="records.read",
            possible_operations=[SecurityOperation.READ],
            resource_type=ResourceType.DATABASE,
            resource_arg="table",
            scope_arg="limit",
            sensitive_output_types={DataType.PUBLIC},
        ),
        read,
    )
    outcome = await harness.runtime.execute(
        RawToolCall(
            tool_name="records.read",
            arguments={"table": "public", "limit": 1000},
            principal="analyst",
            session_id="restricted",
        )
    )

    assert outcome.decision.action == DecisionAction.RESTRICT
    assert received == {"table": "public", "limit": 100}
    assert outcome.request_event.scope == {"argument": "limit", "count": 100}
    assert outcome.result_event is not None


async def test_approval_is_bound_to_session_call_arguments_and_single_use(runtime_factory) -> None:
    harness = runtime_factory()
    executions = 0

    async def delete_file(_):
        nonlocal executions
        executions += 1
        return {"deleted": True}

    harness.runtime.registry.register(
        ToolCapability(
            tool_name="file.delete",
            possible_operations=[SecurityOperation.DELETE],
            resource_type=ResourceType.FILE,
            resource_arg="path",
        ),
        delete_file,
    )
    harness.runtime.registry.register(
        ToolCapability(
            tool_name="file.other_delete",
            possible_operations=[SecurityOperation.DELETE],
            resource_type=ResourceType.FILE,
            resource_arg="path",
        ),
        delete_file,
    )
    call = RawToolCall(
        tool_name="file.delete",
        arguments={"path": "/tmp/report"},
        principal="ops",
        session_id="approval",
        call_id="delete-1",
    )
    pending = await harness.runtime.execute(call)
    assert pending.decision.action == DecisionAction.REQUIRE_APPROVAL
    assert pending.decision.approval_id is not None
    assert executions == 0

    _, token = await harness.runtime.approvals.approve(pending.decision.approval_id)
    wrong_tool = await harness.runtime.execute(
        call.model_copy(update={"tool_name": "file.other_delete", "approval_token": token})
    )
    wrong_arguments = await harness.runtime.execute(
        call.model_copy(
            update={
                "arguments": {"path": "/tmp/other"},
                "approval_token": token,
            }
        )
    )
    allowed = await harness.runtime.execute(call.model_copy(update={"approval_token": token}))
    replay = await harness.runtime.execute(call.model_copy(update={"approval_token": token}))

    assert wrong_tool.decision.action == DecisionAction.BLOCK
    assert wrong_arguments.decision.action == DecisionAction.BLOCK
    assert allowed.decision.action == DecisionAction.ALLOW
    assert allowed.state_updated
    assert replay.decision.action == DecisionAction.BLOCK
    assert "invalid_approval" in replay.decision.rule_ids
    assert executions == 1


def test_rewrite_rejects_argument_expansion() -> None:
    with pytest.raises(ValueError, match="expands"):
        apply_restriction({"limit": 10}, {"limit": 100})
    with pytest.raises(ValueError, match="add or remove"):
        apply_restriction({"limit": 10}, {"limit": 5, "extra": True})


async def test_tool_failure_is_a_result_fact_but_not_a_sensitive_history_event(
    runtime_factory,
) -> None:
    harness = runtime_factory()

    async def fail(_):
        raise OSError("backend unavailable")

    harness.runtime.registry.register(
        ToolCapability(
            tool_name="public.read",
            possible_operations=[SecurityOperation.READ],
            resource_type=ResourceType.DATABASE,
        ),
        fail,
    )
    outcome = await harness.runtime.execute(
        RawToolCall(
            tool_name="public.read",
            principal="analyst",
            session_id="failure",
        )
    )
    state = await harness.runtime.state_manager.get("analyst", "failure")

    assert outcome.execution is not None and not outcome.execution.success
    assert outcome.result_event is not None and outcome.result_event.success is False
    assert state.counters["failed_call_count"] == 1
    assert not state.recent_sensitive_events


async def test_audit_defaults_to_hashes_not_raw_sensitive_payloads(runtime_factory) -> None:
    harness = runtime_factory()
    secret = "highly-sensitive-token-value"

    async def read(_):
        return {"token": secret}

    harness.runtime.registry.register(
        ToolCapability(
            tool_name="credential.read",
            possible_operations=[SecurityOperation.READ],
            resource_type=ResourceType.CREDENTIAL,
            sensitive_output_types={DataType.CREDENTIAL},
        ),
        read,
    )
    await harness.runtime.execute(
        RawToolCall(
            tool_name="credential.read",
            arguments={"credential": secret},
            principal="ops",
            session_id="audit",
        )
    )
    rendered = harness.audit_path.read_text(encoding="utf-8")
    records = [json.loads(line) for line in rendered.splitlines()]

    assert secret not in rendered
    assert {item["event_type"] for item in records} >= {
        "CALL_REQUEST",
        "DECISION",
        "CALL_RESULT",
        "STATE_UPDATE",
    }
