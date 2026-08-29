from __future__ import annotations

from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from agentgate.events.models import RawToolCall
from agentgate.semantics import CanonicalToolCall


class SidecarToolCall(BaseModel):
    model_config = ConfigDict(extra="forbid")

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

    def to_runtime_call(self) -> RawToolCall:
        return RawToolCall(**self.model_dump())

    def to_canonical_call(self) -> CanonicalToolCall:
        return CanonicalToolCall.from_raw(
            self.to_runtime_call(),
            source_framework="custom",
            source_transport="http_sidecar",
        )
