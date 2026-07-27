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
