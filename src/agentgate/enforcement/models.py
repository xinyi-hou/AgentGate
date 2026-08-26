from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field

from agentgate.events.models import utc_now


class ApprovalStatus(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    CONSUMED = "CONSUMED"
    EXPIRED = "EXPIRED"


class ApprovalRequest(BaseModel):
    approval_id: str = Field(default_factory=lambda: str(uuid4()))
    principal: str
    session_id: str
    call_id: str
    tool_name: str
    argument_digest: str
    status: ApprovalStatus = ApprovalStatus.PENDING
    token_hash: str | None = Field(default=None, exclude=True)
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime
    decided_at: datetime | None = None
    consumed_at: datetime | None = None
