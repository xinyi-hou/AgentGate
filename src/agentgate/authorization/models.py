from __future__ import annotations

import hashlib
import json
from datetime import datetime
from uuid import uuid4

from pydantic import BaseModel, Field

from agentgate.events.models import EffectType, SecurityOperation, utc_now


class TaskIntent(BaseModel):
    task_id: str
    goal: str

    @property
    def task_hash(self) -> str:
        payload = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()


class TaskAuthorization(BaseModel):
    authorization_id: str = Field(default_factory=lambda: str(uuid4()))
    principal: str
    task_id: str
    allowed_operations: set[SecurityOperation]
    allowed_resource_patterns: list[str] = Field(default_factory=lambda: ["*"])
    allowed_effects: set[EffectType] = Field(default_factory=set)
    forbidden_effects: set[EffectType] = Field(default_factory=set)
    allowed_destinations: list[str] = Field(default_factory=list)
    max_records: int | None = Field(default=None, ge=0)
    issuer: str
    issued_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = None
    task_hash: str | None = None
    signature: str | None = None
    evidence: list[str] = Field(default_factory=list)
