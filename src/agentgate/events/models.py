from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, model_validator


def utc_now() -> datetime:
    return datetime.now(UTC)


class EventPhase(StrEnum):
    REQUEST = "REQUEST"
    RESULT = "RESULT"


class SecurityOperation(StrEnum):
    UNKNOWN = "UNKNOWN"
    READ = "READ"
    TRANSFORM = "TRANSFORM"
    WRITE = "WRITE"
    SEND = "SEND"
    EXECUTE = "EXECUTE"
    DELETE = "DELETE"
    AUTH = "AUTH"
    PRIVILEGE = "PRIVILEGE"
    INSTALL = "INSTALL"
    DELEGATE = "DELEGATE"


class ResourceType(StrEnum):
    FILE = "FILE"
    DATABASE = "DATABASE"
    MESSAGE = "MESSAGE"
    CREDENTIAL = "CREDENTIAL"
    PROCESS = "PROCESS"
    NETWORK = "NETWORK"
    APPLICATION = "APPLICATION"
    CONFIG = "CONFIG"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    MEMORY = "MEMORY"
    UNKNOWN = "UNKNOWN"


class DataType(StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    PERSONAL = "PERSONAL"
    FINANCIAL = "FINANCIAL"
    CREDENTIAL = "CREDENTIAL"
    SECRET = "SECRET"


class TrustDomain(StrEnum):
    LOCAL = "LOCAL"
    INTERNAL = "INTERNAL"
    TRUSTED_EXTERNAL = "TRUSTED_EXTERNAL"
    UNKNOWN_EXTERNAL = "UNKNOWN_EXTERNAL"


class EffectType(StrEnum):
    EXTERNAL = "EXTERNAL_EFFECT"
    PERSISTENT = "PERSISTENT_EFFECT"
    PRIVILEGED = "PRIVILEGED_EFFECT"
    DESTRUCTIVE = "DESTRUCTIVE_EFFECT"
    IRREVERSIBLE = "IRREVERSIBLE_EFFECT"


class RawToolCall(BaseModel):
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    principal: str
    session_id: str
    call_id: str = Field(default_factory=lambda: str(uuid4()))
    agent_id: str | None = None
    task_id: str | None = None
    parent_call_id: str | None = None
    approval_token: str | None = None
    context_hints: set[str] = Field(default_factory=set)
    timestamp: datetime = Field(default_factory=utc_now)


class ToolExecutionResult(BaseModel):
    output: Any = None
    success: bool = True
    affected_count: int | None = None
    error_type: str | None = None
    error_message: str | None = None
    timestamp: datetime = Field(default_factory=utc_now)


class SecurityAction(BaseModel):
    """One security-relevant effect of a normalized tool invocation."""

    operation: SecurityOperation
    operation_subtype: str | None = None
    resource_type: ResourceType = ResourceType.UNKNOWN
    resource_id: str | None = None
    data_objects: list[str] = Field(default_factory=list)
    data_types: set[DataType] = Field(default_factory=set)
    destination: str | None = None
    destination_type: str | None = None
    trust_domain: TrustDomain = TrustDomain.LOCAL
    effects: set[EffectType] = Field(default_factory=set)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)


class ToolSecurityEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    phase: EventPhase

    principal: str
    session_id: str
    call_id: str
    agent_id: str | None = None
    task_id: str | None = None
    parent_call_id: str | None = None

    tool_name: str
    source_framework: str = "legacy"
    source_transport: str | None = None
    source_metadata: dict[str, Any] = Field(default_factory=dict)
    operation: SecurityOperation
    operation_subtype: str | None = None

    resource_type: ResourceType = ResourceType.UNKNOWN
    resource_id: str | None = None
    scope: dict[str, Any] | None = None
    operand: dict[str, Any] = Field(default_factory=dict)

    data_objects: list[str] = Field(default_factory=list)
    input_data_objects: list[str] = Field(default_factory=list)
    output_data_objects: list[str] = Field(default_factory=list)
    data_types: set[DataType] = Field(default_factory=set)
    sensitivity: set[DataType] = Field(default_factory=set)

    destination: str | None = None
    destination_type: str | None = None
    trust_domain: TrustDomain = TrustDomain.LOCAL

    effects: set[EffectType] = Field(default_factory=set)
    actions: list[SecurityAction] = Field(default_factory=list)

    arguments: dict[str, Any] | None = None
    result: Any = None
    success: bool | None = None
    affected_count: int | None = None

    trusted_source_labels: set[str] = Field(default_factory=set)
    context_hints: set[str] = Field(default_factory=set)
    trust_evidence: list[str] = Field(default_factory=list)
    untrusted_context: bool = False
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def populate_primary_action(self) -> ToolSecurityEvent:
        if not self.actions:
            self.actions = [self.primary_action()]
        return self

    def primary_action(self) -> SecurityAction:
        return SecurityAction(
            operation=self.operation,
            operation_subtype=self.operation_subtype,
            resource_type=self.resource_type,
            resource_id=self.resource_id,
            data_objects=list(self.input_data_objects or self.data_objects),
            data_types=set(self.data_types),
            destination=self.destination,
            destination_type=self.destination_type,
            trust_domain=self.trust_domain,
            effects=set(self.effects),
            confidence=self.confidence,
            evidence=list(self.evidence),
        )
