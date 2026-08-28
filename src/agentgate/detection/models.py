from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Protocol

from pydantic import BaseModel, Field

from agentgate.events.models import utc_now
from agentgate.state.models import SensitiveEventRef


class RuleMatchState(BaseModel):
    principal: str
    session_id: str
    rule_id: str
    policy_version: str
    next_step: int = Field(ge=1)
    matched_call_ids: list[str] = Field(default_factory=list)
    matched_object_ids: list[str] = Field(default_factory=list)
    matched_events: list[SensitiveEventRef] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = None


DetectionState = dict[str, list[RuleMatchState]]
DetectionStateUpdater = Callable[[DetectionState], DetectionState]


class DetectionStateStore(Protocol):
    async def get(
        self,
        principal: str,
        session_id: str,
        policy_version: str,
    ) -> DetectionState: ...

    async def update(
        self,
        principal: str,
        session_id: str,
        policy_version: str,
        updater: DetectionStateUpdater,
    ) -> DetectionState: ...

    async def delete(self, principal: str, session_id: str) -> None: ...
