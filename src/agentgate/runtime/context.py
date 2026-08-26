from __future__ import annotations

from pydantic import BaseModel


class RuntimeContext(BaseModel):
    principal: str
    session_id: str
    agent_id: str | None = None
    task_id: str | None = None
    parent_call_id: str | None = None
    trusted_context: bool = False
    untrusted_context: bool = False
