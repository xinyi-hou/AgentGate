from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class Action(StrEnum):
    READ = "READ"
    WRITE = "WRITE"
    DELETE = "DELETE"
    EXECUTE = "EXECUTE"
    TRANSMIT = "TRANSMIT"
    CONFIGURE = "CONFIGURE"
    UNKNOWN = "UNKNOWN"


class Sensitivity(StrEnum):
    PUBLIC = "Public"
    INTERNAL = "Internal"
    PERSONAL = "Personal"
    CREDENTIAL = "Credential"
    FINANCIAL = "Financial"
    RESTRICTED = "Restricted"


class DecisionAction(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REWRITE = "REWRITE"
    LIMIT_SCOPE = "LIMIT_SCOPE"
    REQUIRE_CONFIRMATION = "REQUIRE_CONFIRMATION"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    SANDBOX = "SANDBOX"
    SANITIZE = "SANITIZE"


class EventPhase(StrEnum):
    REGISTER = "REGISTER"
    PRE_CALL = "PRE_CALL"
    POST_CALL = "POST_CALL"


class ToolProfile(BaseModel):
    tool_name: str
    action: Action = Action.UNKNOWN
    resource: str = "unknown"
    scope: str = "single"
    effects: set[str] = Field(default_factory=set)
    input_sensitivity: dict[str, Sensitivity] = Field(default_factory=dict)
    output_sensitivity: set[Sensitivity] = Field(default_factory=set)
    destination: str = "agent_context"
    provenance: str = "declared"
    requires_confirmation: bool = False
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class ToolSpec(BaseModel):
    name: str
    description: str
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output_schema: dict[str, Any] = Field(default_factory=dict)
    namespace: str = "default"
    source: str = "local"
    publisher: str = "unknown"
    version: str = "1.0.0"
    trusted: bool = False
    dependencies: list[str] = Field(default_factory=list)
    profile: ToolProfile | None = None


class ToolFingerprint(BaseModel):
    structural_hash: str
    semantic_hash: str
    semantic_tokens: tuple[str, ...]


class IntegrityFinding(BaseModel):
    risk_type: str
    severity: int = Field(ge=0, le=10)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str
    source: str = "rule"


class IntegrityResult(BaseModel):
    trust_level: str = "untrusted"
    findings: list[IntegrityFinding] = Field(default_factory=list)
    sanitized_content: str | None = None
    fingerprint: ToolFingerprint | None = None
    profile: ToolProfile | None = None
    blocking_threshold: int = Field(default=8, ge=1, le=10)

    @property
    def blocked(self) -> bool:
        return any(f.severity >= self.blocking_threshold for f in self.findings)


class TaskContract(BaseModel):
    principal: str
    goal: str
    allowed_actions: set[Action]
    allowed_resources: set[str]
    allowed_effects: set[str] = Field(default_factory=set)
    forbidden_effects: set[str] = Field(default_factory=set)
    purpose: str = "task"
    tenant: str | None = None
    max_records: int = Field(default=1, ge=0)
    external_transmission: bool = False
    allowed_destinations: set[str] = Field(default_factory=set)
    confirmed_actions: set[Action] = Field(default_factory=set)
    approval_tokens: set[str] = Field(default_factory=set)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolCall(BaseModel):
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    principal: str
    session_id: str
    call_id: str = Field(default_factory=lambda: str(uuid4()))
    parent_call_id: str | None = None
    approval_token: str | None = None
    data_labels: set[Sensitivity] = Field(default_factory=set)
    rationale: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class CallEffect(BaseModel):
    action: Action
    resource: str
    scope: str = "single"
    record_count: int = 1
    data_access: set[str] = Field(default_factory=set)
    effects: set[str] = Field(default_factory=set)
    destination: str = "agent_context"
    reversible: bool = True


class Decision(BaseModel):
    action: DecisionAction
    risk_types: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    rewritten_arguments: dict[str, Any] | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    module: str = "runtime"

    @property
    def permits_execution(self) -> bool:
        return self.action in {
            DecisionAction.ALLOW,
            DecisionAction.REWRITE,
            DecisionAction.LIMIT_SCOPE,
        }


class ToolResult(BaseModel):
    call_id: str
    tool_name: str
    output: Any
    success: bool = True
    resource: str | None = None
    record_count: int = 0
    data_labels: set[Sensitivity] = Field(default_factory=set)
    side_effects: set[str] = Field(default_factory=set)
    destination: str = "agent_context"
    security_metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class GatewayOutcome(BaseModel):
    decision: Decision
    call: ToolCall | None = None
    result: ToolResult | None = None
    module_decisions: list[Decision] = Field(default_factory=list)
