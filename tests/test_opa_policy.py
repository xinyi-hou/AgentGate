from __future__ import annotations

import httpx

from agentgate.models import DecisionAction
from agentgate.policy import OpaPolicyBackend


async def test_opa_backend_uses_data_api(monkeypatch) -> None:
    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self):
            return {"result": {"action": "ALLOW", "reasons": []}}

    class FakeClient:
        def __init__(self, *args, **kwargs):
            self.requests = []

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, url, json):
            assert url.endswith("/v1/data/agentgate/authorization/decision")
            assert "input" in json
            return FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    backend = OpaPolicyBackend("http://opa:8181", "agentgate/authorization/decision")
    result = await backend.decide({"checks": {"action": True}})
    assert result["action"] == DecisionAction.ALLOW
