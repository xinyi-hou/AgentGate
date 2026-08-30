from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class AtgSnapshot(BaseModel):
    agent_nodes: int = 0
    tool_event_nodes: int = 0
    resource_nodes: int = 0
    data_object_nodes: int = 0
    trust_domain_nodes: int = 0
    edges: int = 0
    provenance_edges: int = 0
    dependency_edges_constructed: int = 0
    produces_edges: int = 0
    consumes_edges: int = 0
    derives_from_edges: int = 0
    propagated_label_count: int = 0
    max_provenance_depth: int = 0
    graph_memory_bytes: int = 0


class ArtifactPaths(BaseModel):
    trace_path: str = ""
    atg_path: str = ""
    decision_log_path: str = ""


class TaskRunRecord(BaseModel):
    experiment_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    benchmark: str
    benchmark_commit: str
    case_id: str
    attack_type: str = "benign"
    is_attack: bool
    applicable_to_agentgate: bool = True
    applicability_reason: str = ""
    single_step: bool = False
    multi_step: bool = False
    single_server: bool = True
    multi_server: bool = False
    requires_provenance: bool = False
    requires_metadata_inspection: bool = False
    paired_case_id: str | None = None

    defense: str
    defense_version: str
    defense_commit: str
    defense_config_hash: str
    agent_model: str
    semantic_model: str = "rules-only"
    seed: int = 0

    task_success: bool
    attack_success: bool
    harmful_side_effect_occurred: bool
    attack_prevented_before_side_effect: bool = False
    late_detection: bool = False
    benign_degraded: bool = False

    blocked: bool
    block_step: int | None = None
    first_block_step: int | None = None
    tool_calls_before_block: int | None = None
    block_phase: Literal["discovery", "request", "result-derived-next-request", "none"] = "none"
    decision: str = "ALLOW"
    matched_rules: list[str] = Field(default_factory=list)

    tool_calls: int
    turns: int
    trajectory_length: int
    tool_call_successes: int = 0

    end_to_end_latency_ms: float = 0.0
    agentgate_total_ms: float = 0.0
    upstream_tool_ms: float = 0.0
    semantic_input_tokens: int = 0
    semantic_output_tokens: int = 0
    semantic_requests: int = 0
    semantic_failures: int = 0
    retry_count: int = 0
    process_rss_bytes: int = 0
    peak_memory_bytes: int = 0

    first_risky_source_event_id: str | None = None
    blocked_sink_event_id: str | None = None
    block_provenance_depth: int | None = None
    atg: AtgSnapshot = Field(default_factory=AtgSnapshot)
    artifacts: ArtifactPaths = Field(default_factory=ArtifactPaths)
    notes: list[str] = Field(default_factory=list)


class CallRunRecord(BaseModel):
    experiment_id: str
    benchmark: str
    case_id: str
    call_index: int
    call_id: str
    tool_name: str
    operation: str
    arguments_digest: str
    decision: str
    rule_ids: list[str] = Field(default_factory=list)
    executed: bool
    success: bool | None = None
    side_effects_before: int = 0
    side_effects_after: int = 0
    adapter_parse_ms: float = 0.0
    canonicalization_ms: float = 0.0
    semantic_resolution_ms: float = 0.0
    graph_update_ms: float = 0.0
    provenance_resolution_ms: float = 0.0
    policy_eval_ms: float = 0.0
    control_action_ms: float = 0.0
    agentgate_total_ms: float = 0.0
    upstream_tool_ms: float = 0.0
    llm_called: bool = False
    llm_latency_ms: float = 0.0


class IntegrationFailure(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    component: str
    repository: str = ""
    revision: str = ""
    phase: str
    reason: str
    reproducible_command: str = ""
    blocking_requirement: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
