from __future__ import annotations

from agentgate.audit.jsonl import JsonlAuditStore
from agentgate.audit.sqlite import SqliteAuditStore
from agentgate.capabilities.registry import CapabilityRegistry
from agentgate.config import AgentGateSettings
from agentgate.detection.engine import DetectionEngine
from agentgate.enforcement.approval import ApprovalManager
from agentgate.events.normalizer import ToolEventBuilder
from agentgate.policy.loader import load_policy
from agentgate.runtime.gateway import AgentGateRuntime
from agentgate.state.manager import StateManager
from agentgate.state.memory_store import MemoryStateStore
from agentgate.state.models import StateStore
from agentgate.state.redis_store import RedisStateStore


def build_runtime(
    settings: AgentGateSettings | None = None,
    *,
    registry: CapabilityRegistry | None = None,
    state_store: StateStore | None = None,
) -> AgentGateRuntime:
    settings = settings or AgentGateSettings.from_env()
    if state_store is None:
        state_store = (
            RedisStateStore(settings.redis_url, ttl_seconds=settings.session_ttl_seconds)
            if settings.redis_url
            else MemoryStateStore(ttl_seconds=settings.session_ttl_seconds)
        )
    policy = load_policy(settings.policy_path)
    required_history_ttl = max(
        [settings.history_ttl_seconds]
        + [rule.window_seconds for rule in policy.aggregate_rules]
        + [
            rule.constraints.max_interval_seconds
            for rule in policy.sequence_rules
            if rule.constraints.max_interval_seconds is not None
        ]
    )
    audit = (
        SqliteAuditStore(
            settings.audit_path,
            unsafe_debug_payloads=settings.unsafe_debug_audit_payloads,
        )
        if settings.audit_backend == "sqlite"
        else JsonlAuditStore(
            settings.audit_path,
            unsafe_debug_payloads=settings.unsafe_debug_audit_payloads,
        )
    )
    return AgentGateRuntime(
        registry=registry or CapabilityRegistry(),
        event_builder=ToolEventBuilder(
            internal_domains=settings.internal_domains,
            trusted_external_domains=settings.trusted_external_domains,
        ),
        state_manager=StateManager(
            state_store,
            history_limit=settings.history_limit,
            history_ttl_seconds=required_history_ttl,
        ),
        detector=DetectionEngine(policy),
        approvals=ApprovalManager(ttl_seconds=settings.approval_ttl_seconds),
        audit=audit,
    )
