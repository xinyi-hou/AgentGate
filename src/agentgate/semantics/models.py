from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from agentgate.events.models import (
    DataType,
    EffectType,
    RawToolCall,
    ResourceType,
    SecurityOperation,
    utc_now,
)


class CanonicalToolCall(BaseModel):
    """Framework-neutral structural representation of one requested tool call."""

    call_id: str = Field(default_factory=lambda: str(uuid4()))
    tool_id: str | None = None
    tool_name: str

    principal_id: str
    agent_id: str | None = None
    session_id: str
    task_id: str | None = None
    parent_call_id: str | None = None

    arguments: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=utc_now)

    source_framework: str
    source_transport: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    # Enforcement inputs remain structural; they do not assert trust or permission.
    approval_token: str | None = None
    context_hints: set[str] = Field(default_factory=set)

    @classmethod
    def from_raw(
        cls,
        call: RawToolCall,
        *,
        source_framework: str = "legacy",
        source_transport: str | None = None,
    ) -> CanonicalToolCall:
        return cls(
            call_id=call.call_id,
            tool_name=call.tool_name,
            principal_id=call.principal,
            agent_id=call.agent_id,
            session_id=call.session_id,
            task_id=call.task_id,
            parent_call_id=call.parent_call_id,
            arguments=call.arguments,
            timestamp=call.timestamp,
            source_framework=source_framework,
            source_transport=source_transport,
            approval_token=call.approval_token,
            context_hints=call.context_hints,
        )

    def to_raw(self) -> RawToolCall:
        return RawToolCall(
            tool_name=self.tool_name,
            arguments=self.arguments,
            principal=self.principal_id,
            session_id=self.session_id,
            call_id=self.call_id,
            agent_id=self.agent_id,
            task_id=self.task_id,
            parent_call_id=self.parent_call_id,
            approval_token=self.approval_token,
            context_hints=self.context_hints,
            timestamp=self.timestamp,
        )


class SemanticResolution(BaseModel):
    """Behavior-neutral facts returned by an optional semantic resolver."""

    model_config = ConfigDict(extra="forbid")

    operation: SecurityOperation | None = None
    resource_type: ResourceType | None = None
    resource_arg: str | None = None
    scope_arg: str | None = None
    destination_arg: str | None = None
    payload_args: list[str] = Field(default_factory=list)
    input_data_types: set[DataType] = Field(default_factory=set)
    output_data_types: set[DataType] = Field(default_factory=set)
    effects: set[EffectType] = Field(default_factory=set)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)


class SemanticResolver(Protocol):
    async def resolve(
        self,
        *,
        name: str,
        description: str,
        input_schema: dict[str, Any],
        output_schema: dict[str, Any],
        candidates: list[SecurityOperation],
        reason: str,
    ) -> SemanticResolution | None: ...


class SemanticResolutionTrace(BaseModel):
    resolver_called: bool = False
    resolver_reason: str | None = None
    resolver_latency_ms: float | None = None
    resolver_source: str | None = None
