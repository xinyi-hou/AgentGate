from __future__ import annotations

from pydantic import BaseModel, Field


class RuntimeContext(BaseModel):
    """Identity and trust facts supplied by a trusted adapter or orchestrator."""

    principal: str
    session_id: str
    agent_id: str | None = None
    task_id: str | None = None
    parent_call_id: str | None = None
    authorization_id: str | None = None
    trusted_source_labels: set[str] = Field(default_factory=set)
