from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, Field

from agentgate.events.models import (
    DataType,
    EffectType,
    ResourceType,
    SecurityOperation,
    TrustDomain,
    utc_now,
)


class StateLabel(StrEnum):
    HAS_PERSONAL_DATA = "HAS_PERSONAL_DATA"
    HAS_FINANCIAL_DATA = "HAS_FINANCIAL_DATA"
    HAS_CREDENTIAL = "HAS_CREDENTIAL"
    HAS_SECRET = "HAS_SECRET"
    EXPOSED_TO_UNTRUSTED_CONTENT = "EXPOSED_TO_UNTRUSTED_CONTENT"
    USED_EXTERNAL_COMMUNICATION = "USED_EXTERNAL_COMMUNICATION"
    USED_PRIVILEGED_OPERATION = "USED_PRIVILEGED_OPERATION"
    USED_DESTRUCTIVE_OPERATION = "USED_DESTRUCTIVE_OPERATION"
    REQUIRES_APPROVAL = "REQUIRES_APPROVAL"
    ISOLATED = "ISOLATED"


DEFAULT_COUNTERS = {
    "records_read": 0,
    "sensitive_records_read": 0,
    "personal_records_read": 0,
    "external_send_count": 0,
    "execute_count": 0,
    "privileged_action_count": 0,
    "delete_count": 0,
    "install_count": 0,
    "failed_call_count": 0,
}


class SensitiveObject(BaseModel):
    object_id: str
    data_type: DataType
    sensitivity: DataType
    source_resource: str | None = None
    producer_call_id: str
    parent_object_ids: list[str] = Field(default_factory=list)
    fingerprints: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)


class SensitiveEventRef(BaseModel):
    call_id: str
    task_id: str | None = None
    operation: SecurityOperation
    subtype: str | None = None
    resource_type: ResourceType = ResourceType.UNKNOWN
    resource_id: str | None = None
    object_ids: list[str] = Field(default_factory=list)
    data_types: set[DataType] = Field(default_factory=set)
    destination: str | None = None
    trust_domain: TrustDomain = TrustDomain.LOCAL
    effects: set[EffectType] = Field(default_factory=set)
    affected_count: int = 0
    timestamp: datetime = Field(default_factory=utc_now)


class SessionSecurityState(BaseModel):
    principal: str
    session_id: str
    labels: set[StateLabel] = Field(default_factory=set)
    counters: dict[str, int] = Field(default_factory=lambda: dict(DEFAULT_COUNTERS))
    sensitive_objects: dict[str, SensitiveObject] = Field(default_factory=dict)
    recent_sensitive_events: list[SensitiveEventRef] = Field(default_factory=list)
    isolated: bool = False
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


StateUpdater = Callable[[SessionSecurityState], SessionSecurityState]


class StateStore(Protocol):
    async def get(self, principal: str, session_id: str) -> SessionSecurityState: ...

    async def update(
        self,
        principal: str,
        session_id: str,
        updater: StateUpdater,
    ) -> SessionSecurityState: ...

    async def delete(self, principal: str, session_id: str) -> None: ...
