from __future__ import annotations

import base64

import pytest

from agentgate.events import (
    DataType,
    EventPhase,
    ResourceType,
    SecurityOperation,
    ToolSecurityEvent,
    TrustDomain,
)
from agentgate.state import MemoryStateStore, StateLabel, StateManager
from agentgate.state.provenance import match_sensitive_objects


def result_event(**updates) -> ToolSecurityEvent:
    payload = {
        "phase": EventPhase.RESULT,
        "principal": "support",
        "session_id": "session",
        "call_id": "call-1",
        "tool_name": "customer.read",
        "operation": SecurityOperation.READ,
        "resource_type": ResourceType.DATABASE,
        "resource_id": "customer:C1",
        "data_types": {DataType.PERSONAL},
        "sensitivity": {DataType.PERSONAL},
        "result": {"email": "alice@example.test"},
        "success": True,
        "affected_count": 1,
    }
    payload.update(updates)
    return ToolSecurityEvent.model_validate(payload)


async def test_state_rejects_request_phase_updates() -> None:
    manager = StateManager(MemoryStateStore())
    event = result_event(phase=EventPhase.REQUEST, success=None, result=None)
    with pytest.raises(ValueError, match="RESULT"):
        await manager.observe(event)


async def test_executed_sensitive_read_updates_labels_counters_objects_and_history() -> None:
    manager = StateManager(MemoryStateStore())
    event = result_event()
    state = await manager.observe(event)

    assert StateLabel.HAS_PERSONAL_DATA in state.labels
    assert state.counters["records_read"] == 1
    assert state.counters["sensitive_records_read"] == 1
    assert len(state.sensitive_objects) == 1
    assert state.recent_sensitive_events[0].call_id == "call-1"
    assert event.data_objects == list(state.sensitive_objects)


async def test_failed_call_updates_only_failure_counter() -> None:
    manager = StateManager(MemoryStateStore())
    state = await manager.observe(
        result_event(success=False, result=None, data_types=set(), sensitivity=set())
    )
    assert state.counters["failed_call_count"] == 1
    assert not state.labels
    assert not state.sensitive_objects
    assert not state.recent_sensitive_events


async def test_provenance_matches_encoded_values_and_propagates_through_write() -> None:
    manager = StateManager(MemoryStateStore())
    source = result_event(
        call_id="source",
        data_types={DataType.CREDENTIAL},
        sensitivity={DataType.CREDENTIAL},
        result={"token": "deploy-secret-value"},
    )
    source_state = await manager.observe(source)
    assert "deploy-secret-value" not in source_state.model_dump_json()
    encoded = base64.b64encode(b"deploy-secret-value").decode()
    matches = match_sensitive_objects({"content": encoded}, source_state.sensitive_objects.values())
    assert len(matches) == 1

    written = result_event(
        call_id="write",
        operation=SecurityOperation.WRITE,
        resource_type=ResourceType.FILE,
        resource_id="/tmp/deploy.sh",
        data_objects=[matches[0].object_id],
        data_types={DataType.CREDENTIAL},
        sensitivity={DataType.CREDENTIAL},
        result={"path": "/tmp/deploy.sh", "written": True},
    )
    state = await manager.observe(written)
    produced = [
        item for item in state.sensitive_objects.values() if item.producer_call_id == "write"
    ]
    assert produced[0].parent_object_ids == [matches[0].object_id]
    assert match_sensitive_objects({"path": "/tmp/deploy.sh"}, produced)


async def test_external_read_records_untrusted_exposure_fact() -> None:
    manager = StateManager(MemoryStateStore())
    state = await manager.observe(
        result_event(
            trust_domain=TrustDomain.UNKNOWN_EXTERNAL,
            untrusted_context=True,
            data_types={DataType.INTERNAL},
            sensitivity={DataType.INTERNAL},
        )
    )
    assert StateLabel.EXPOSED_TO_UNTRUSTED_CONTENT in state.labels


async def test_same_session_identifier_is_partitioned_by_principal() -> None:
    store = MemoryStateStore()
    alice = await store.get("alice", "shared")
    bob = await store.get("bob", "shared")
    assert alice.principal == "alice"
    assert bob.principal == "bob"
    assert alice is not bob
