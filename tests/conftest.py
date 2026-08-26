from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from agentgate.audit import JsonlAuditStore
from agentgate.capabilities import CapabilityRegistry
from agentgate.detection import DetectionEngine
from agentgate.enforcement import ApprovalManager
from agentgate.events import ToolEventBuilder
from agentgate.policy import SecurityPolicy, load_policy
from agentgate.runtime import AgentGateRuntime
from agentgate.state import MemoryStateStore, StateManager


@dataclass
class RuntimeHarness:
    runtime: AgentGateRuntime
    audit_path: Path


@pytest.fixture
def runtime_factory(tmp_path: Path):
    counter = 0

    def build(
        policy: SecurityPolicy | None = None,
        *,
        internal_domains: set[str] | None = None,
        trusted_external_domains: set[str] | None = None,
    ) -> RuntimeHarness:
        nonlocal counter
        counter += 1
        audit_path = tmp_path / f"audit-{counter}.jsonl"
        runtime = AgentGateRuntime(
            registry=CapabilityRegistry(),
            event_builder=ToolEventBuilder(
                internal_domains=internal_domains,
                trusted_external_domains=trusted_external_domains,
            ),
            state_manager=StateManager(MemoryStateStore()),
            detector=DetectionEngine(policy or load_policy()),
            approvals=ApprovalManager(),
            audit=JsonlAuditStore(audit_path),
        )
        return RuntimeHarness(runtime=runtime, audit_path=audit_path)

    return build
