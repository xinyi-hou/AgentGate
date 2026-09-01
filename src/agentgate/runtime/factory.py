from __future__ import annotations

import os

from agentgate.audit.jsonl import JsonlAuditStore
from agentgate.audit.sqlite import SqliteAuditStore
from agentgate.capabilities.inference import CapabilityInferer
from agentgate.capabilities.registry import CapabilityRegistry
from agentgate.config import AgentGateSettings
from agentgate.content import ContentMode
from agentgate.detection.engine import DetectionEngine
from agentgate.detection.graph_engine import GraphRiskEngine
from agentgate.detection.memory_store import MemoryDetectionStateStore
from agentgate.detection.redis_store import RedisDetectionStateStore
from agentgate.detection.structured import StructuredGraphRiskResolver
from agentgate.enforcement.approval import ApprovalManager
from agentgate.enforcement.coordinator import (
    LocalSessionExecutionCoordinator,
    RedisSessionExecutionCoordinator,
)
from agentgate.events.normalizer import ToolEventBuilder
from agentgate.graph import AgentTransitionGraphBuilder, InMemoryGraphStore, RedisGraphStore
from agentgate.policy.loader import load_policy
from agentgate.provenance import StructuredDependencyResolver
from agentgate.runtime.gateway import AgentGateRuntime
from agentgate.semantics import (
    OpenAICompatibleCompletion,
    OpenAICompatibleConfig,
    StructuredSemanticResolver,
)
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
    completion = _llm_completion(settings)
    capability_inferer = CapabilityInferer(
        semantic_resolver=(StructuredSemanticResolver(completion) if completion else None),
        llm_confidence_threshold=settings.llm_confidence_threshold,
    )
    if state_store is None:
        state_store = (
            RedisStateStore(settings.redis_url, ttl_seconds=settings.session_ttl_seconds)
            if settings.redis_url
            else MemoryStateStore(ttl_seconds=settings.session_ttl_seconds)
        )
    detection_store = (
        RedisDetectionStateStore(
            settings.redis_url,
            ttl_seconds=settings.session_ttl_seconds,
        )
        if settings.redis_url
        else MemoryDetectionStateStore(ttl_seconds=settings.session_ttl_seconds)
    )
    coordinator = (
        RedisSessionExecutionCoordinator(settings.redis_url)
        if settings.redis_url
        else LocalSessionExecutionCoordinator()
    )
    graph_store = (
        RedisGraphStore(settings.redis_url, ttl_seconds=settings.session_ttl_seconds)
        if settings.redis_url
        else InMemoryGraphStore(ttl_seconds=settings.session_ttl_seconds)
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
            label_ttl_seconds=settings.label_ttl_seconds,
        ),
        detector=DetectionEngine(policy, detection_store),
        approvals=ApprovalManager(ttl_seconds=settings.approval_ttl_seconds),
        audit=audit,
        content_mode=ContentMode(settings.content_mode),
        coordinator=coordinator,
        graph_store=graph_store,
        graph_builder=AgentTransitionGraphBuilder(
            dependency_resolver=(StructuredDependencyResolver(completion) if completion else None),
        ),
        graph_detector=GraphRiskEngine(
            policy,
            resolver=(StructuredGraphRiskResolver(completion) if completion else None),
        ),
        capability_inferer=capability_inferer,
        llm_completion=completion,
        llm_model=settings.llm_model if completion else None,
        research_debug=settings.research_debug,
    )


def _llm_completion(settings: AgentGateSettings) -> OpenAICompatibleCompletion | None:
    if not settings.llm_enabled:
        return None
    base_url = settings.llm_base_url
    api_key = settings.llm_api_key
    if base_url is None:
        base_url = os.getenv("AGENTGATE_LLM_URL") or os.getenv("LLM_URL")
    if api_key is None:
        raw_key = os.getenv("AGENTGATE_LLM_API_KEY") or os.getenv("LLM_API")
        api_key_value = raw_key
    else:
        api_key_value = api_key.get_secret_value()
    if not base_url or not api_key_value:
        if settings.llm_required:
            raise RuntimeError(
                "LLM is required; configure LLM_URL and LLM_API "
                "or set AGENTGATE_LLM_REQUIRED=false"
            )
        return None
    return OpenAICompatibleCompletion(
        OpenAICompatibleConfig(
            base_url=base_url,
            api_key=api_key_value,
            model=settings.llm_model,
        ),
        timeout_seconds=settings.llm_timeout_seconds,
        max_attempts=settings.llm_max_attempts,
    )
