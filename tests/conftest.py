from __future__ import annotations

from pathlib import Path

import pytest

from agentgate.config import AgentGateSettings
from agentgate.runtime.gateway import AgentGate
from agentgate.tools import MockBackend, build_default_registry


@pytest.fixture
async def gateway(tmp_path: Path) -> AgentGate:
    registry, _ = build_default_registry(MockBackend())
    settings = AgentGateSettings(audit_path=tmp_path / "audit.jsonl")
    gate = AgentGate.create(settings, registry)
    await gate.initialize()
    return gate
