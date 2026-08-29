from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from agentgate.events.models import utc_now


class AuditEventType(StrEnum):
    CALL_REQUEST = "CALL_REQUEST"
    DECISION = "DECISION"
    CALL_RESULT = "CALL_RESULT"
    STATE_UPDATE = "STATE_UPDATE"
    GRAPH_UPDATE = "GRAPH_UPDATE"
    RULE_MATCH = "RULE_MATCH"
    APPROVAL = "APPROVAL"


class AuditRecord(BaseModel):
    record_id: str = Field(default_factory=lambda: str(uuid4()))
    event_type: AuditEventType
    principal: str
    session_id: str
    call_id: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=utc_now)
