from __future__ import annotations

from fastapi.testclient import TestClient

from agentgate.api import create_app
from agentgate.capabilities import ToolCapability
from agentgate.events import DataType, ResourceType, SecurityOperation
from agentgate.policy.models import DecisionAction, EventCondition, EventRule, SecurityPolicy


def test_sidecar_exposes_registration_execution_state_events_and_policy(runtime_factory) -> None:
    harness = runtime_factory()
    harness.runtime.research_debug = True

    async def read(arguments):
        return {"email": "alice@example.test", "id": arguments["id"]}

    harness.runtime.registry.register(
        ToolCapability(
            tool_name="customer.read",
            possible_operations=[SecurityOperation.READ],
            resource_type=ResourceType.DATABASE,
            resource_arg="id",
            sensitive_output_types={DataType.PERSONAL},
        ),
        read,
    )
    with TestClient(create_app(harness.runtime)) as client:
        health = client.get("/health")
        openapi = client.get("/openapi.json")
        executed = client.post(
            "/v1/calls/execute",
            json={
                "tool_name": "customer.read",
                "arguments": {"id": "C1"},
                "principal": "support",
                "session_id": "api",
            },
        )
        state = client.get("/v1/sessions/api/state", params={"principal": "support"})
        events = client.get("/v1/sessions/api/events", params={"principal": "support"})
        policies = client.get("/v1/policies")
        audit = client.get("/v1/audit", params={"principal": "support", "session_id": "api"})
        graph = client.get("/v1/sessions/api/graph", params={"principal": "support"})
        evidence = client.get(
            f"/v1/decisions/{executed.json()['decision']['decision_id']}/evidence"
        )

    assert health.json()["registered_tools"] == 1
    assert openapi.json()["info"]["version"] == "0.6.0"
    assert executed.status_code == 200
    assert "trusted_context" not in executed.json()["request_event"]
    assert executed.json()["result_event"]["phase"] == "RESULT"
    assert state.json()["labels"] == ["HAS_PERSONAL_DATA"]
    assert state.json()["label_facts"]
    assert "fingerprints" not in state.text
    assert events.json()[0]["operation"] == "READ"
    assert len(policies.json()["sequence_rules"]) >= 5
    assert {item["event_type"] for item in audit.json()} >= {"CALL_REQUEST", "CALL_RESULT"}
    assert {item["node_type"] for item in graph.json()["nodes"]} >= {
        "AGENT",
        "TOOL_EVENT",
        "RESOURCE",
        "DATA",
    }
    assert "fingerprints" not in graph.text
    assert evidence.status_code == 200
    assert evidence.json()["decision"]["decision_id"] == executed.json()["decision"]["decision_id"]


def test_sidecar_registers_evaluation_only_capabilities(runtime_factory) -> None:
    harness = runtime_factory()
    capability = {
        "tool_name": "report.read",
        "possible_operations": ["READ"],
        "resource_type": "FILE",
        "resource_arg": "path",
    }
    with TestClient(create_app(harness.runtime)) as client:
        registered = client.post("/v1/tools/register", json={"capability": capability})
        evaluated = client.post(
            "/v1/calls/evaluate",
            json={
                "tool_name": "report.read",
                "arguments": {"path": "/reports/summary"},
                "principal": "analyst",
                "session_id": "evaluate-only",
            },
        )
        execution = client.post(
            "/v1/calls/execute",
            json={
                "tool_name": "report.read",
                "arguments": {"path": "/reports/summary"},
                "principal": "analyst",
                "session_id": "evaluate-only",
            },
        )
        state = client.get("/v1/sessions/evaluate-only/state", params={"principal": "analyst"})

    assert registered.status_code == 200
    assert evaluated.json()["decision"]["action"] == "ALLOW"
    assert evaluated.json()["advisory_only"] is True
    assert execution.status_code == 409
    assert state.json()["counters"]["records_read"] == 0


def test_sidecar_can_generate_capability_from_tool_declaration(runtime_factory) -> None:
    harness = runtime_factory()
    with TestClient(create_app(harness.runtime)) as client:
        registered = client.post(
            "/v1/tools/register",
            json={
                "name": "customer_read",
                "description": "Read one customer database record.",
                "input_schema": {
                    "type": "object",
                    "properties": {"customer_id": {"type": "string"}},
                },
                "output_schema": {
                    "type": "object",
                    "properties": {"email": {"type": "string"}},
                },
            },
        )
        capability = client.get("/v1/tools/customer_read/capability")

    payload = registered.json()
    assert registered.status_code == 200
    assert payload["possible_operations"] == ["READ"]
    assert payload["sensitive_output_types"] == ["PERSONAL"]
    assert payload["source"] == "schema_inference"
    assert payload["structural_hash"] and payload["evidence"]
    assert capability.status_code == 200
    assert capability.json()["inferred_fields"]["operation"]["value"] == "READ"


def test_rule_state_debug_endpoint_is_separate_from_fact_state(runtime_factory) -> None:
    harness = runtime_factory()
    harness.runtime.research_debug = True

    async def read(_):
        return {"email": "alice@example.test"}

    harness.runtime.registry.register(
        ToolCapability(
            tool_name="customer.read",
            possible_operations=[SecurityOperation.READ],
            sensitive_output_types={DataType.PERSONAL},
        ),
        read,
    )
    with TestClient(create_app(harness.runtime)) as client:
        client.post(
            "/v1/calls/execute",
            json={
                "tool_name": "customer.read",
                "principal": "analyst",
                "session_id": "debug-state",
            },
        )
        facts = client.get(
            "/v1/sessions/debug-state/state",
            params={"principal": "analyst"},
        )
        rules = client.get(
            "/v1/sessions/debug-state/rule-state",
            params={"principal": "analyst"},
        )

    assert facts.status_code == 200
    assert "rule_id" not in facts.text
    assert rules.status_code == 200
    assert any(item["rule_id"] == "sensitive_data_exfiltration" for item in rules.json())


def test_sidecar_approval_flow_returns_token_once_and_executes_bound_call(runtime_factory) -> None:
    harness = runtime_factory(
        SecurityPolicy(
            event_rules=[
                EventRule(
                    id="test_delete_approval",
                    name="Test delete approval",
                    condition=EventCondition(operations={SecurityOperation.DELETE}),
                    action=DecisionAction.REQUIRE_APPROVAL,
                    reason="Exercise the approval protocol.",
                )
            ]
        )
    )
    executions = 0

    async def delete(_):
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
        delete,
    )
    call = {
        "tool_name": "file.delete",
        "arguments": {"path": "/tmp/item"},
        "principal": "ops",
        "session_id": "api-approval",
        "call_id": "delete-api-1",
    }
    with TestClient(create_app(harness.runtime)) as client:
        pending = client.post("/v1/calls/execute", json=call).json()
        approval_id = pending["decision"]["approval_id"]
        grant = client.post(f"/v1/approvals/{approval_id}/approve").json()
        call["approval_token"] = grant["approval_token"]
        allowed = client.post("/v1/calls/execute", json=call)

    assert "token_hash" not in grant["approval"]
    assert allowed.json()["decision"]["action"] == "ALLOW"
    assert executions == 1
