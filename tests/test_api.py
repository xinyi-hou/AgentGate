from __future__ import annotations

from fastapi.testclient import TestClient

from agentgate.runtime.api import app


def test_sidecar_health_and_tool_listing() -> None:
    with TestClient(app) as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["tools"] == 26
        tools = client.get("/v1/tools")
        assert tools.status_code == 200
        assert len(tools.json()) == 26


def test_sidecar_builds_task_contract() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/v1/contracts/build",
            json={
                "task": "query order A102",
                "principal": "support",
                "entitlements": {
                    "actions": ["READ"],
                    "resources": ["order:*"],
                },
            },
        )
    assert response.status_code == 200
    body = response.json()
    assert body["allowed_actions"] == ["READ"]
    assert body["allowed_resources"] == ["order:A102"]


def test_sidecar_executes_from_natural_language_task() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/v1/calls/execute-task",
            json={
                "task": "query order A102",
                "entitlements": {
                    "actions": ["READ"],
                    "resources": ["order:*"],
                },
                "call": {
                    "tool_name": "business.get_order",
                    "arguments": {"order_id": "A102"},
                    "principal": "support",
                    "session_id": "api-semantic-task",
                },
            },
        )
    assert response.status_code == 200
    body = response.json()
    assert body["decision"]["action"] == "ALLOW"
    assert body["result"]["output"]["order_id"] == "A102"
