from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from agentgate.api.dependencies import get_runtime
from agentgate.events.models import (
    DataType,
    EffectType,
    ResourceType,
    SecurityOperation,
    TrustDomain,
)
from agentgate.runtime.gateway import AgentGateRuntime
from agentgate.state.models import SessionSecurityState, StateLabel
from agentgate.state.provenance import digest_payload

router = APIRouter(prefix="/v1/sessions", tags=["sessions"])


class SensitiveObjectView(BaseModel):
    object_id: str
    data_type: DataType
    producer_call_id: str
    parent_object_ids: list[str] = Field(default_factory=list)
    source_resource_digest: str | None = None


class SensitiveEventView(BaseModel):
    call_id: str
    operation: SecurityOperation
    subtype: str | None = None
    resource_type: ResourceType
    resource_digest: str | None = None
    object_ids: list[str] = Field(default_factory=list)
    data_types: set[DataType] = Field(default_factory=set)
    destination_digest: str | None = None
    trust_domain: TrustDomain
    effects: set[EffectType] = Field(default_factory=set)
    affected_count: int = 0


class SequenceProgressView(BaseModel):
    rule_id: str
    next_step: int
    matched_call_ids: list[str]
    matched_object_ids: list[str]
    started_at: datetime
    updated_at: datetime


class SessionStateView(BaseModel):
    principal: str
    session_id: str
    labels: set[StateLabel]
    counters: dict[str, int]
    sensitive_objects: list[SensitiveObjectView]
    sequence_progress: list[SequenceProgressView]


@router.get("/{session_id}/state", response_model=SessionStateView)
async def get_session_state(
    session_id: str,
    principal: Annotated[str, Query(min_length=1)],
    runtime: Annotated[AgentGateRuntime, Depends(get_runtime)],
) -> SessionStateView:
    state = await runtime.state_manager.get(principal, session_id)
    return _state_view(state)


@router.get("/{session_id}/events", response_model=list[SensitiveEventView])
async def get_session_events(
    session_id: str,
    principal: Annotated[str, Query(min_length=1)],
    runtime: Annotated[AgentGateRuntime, Depends(get_runtime)],
) -> list[SensitiveEventView]:
    state = await runtime.state_manager.get(principal, session_id)
    return [
        SensitiveEventView(
            call_id=item.call_id,
            operation=item.operation,
            subtype=item.subtype,
            resource_type=item.resource_type,
            resource_digest=digest_payload(item.resource_id) if item.resource_id else None,
            object_ids=item.object_ids,
            data_types=item.data_types,
            destination_digest=digest_payload(item.destination) if item.destination else None,
            trust_domain=item.trust_domain,
            effects=item.effects,
            affected_count=item.affected_count,
        )
        for item in state.recent_sensitive_events
    ]


def _state_view(state: SessionSecurityState) -> SessionStateView:
    return SessionStateView(
        principal=state.principal,
        session_id=state.session_id,
        labels=state.labels,
        counters=state.counters,
        sensitive_objects=[
            SensitiveObjectView(
                object_id=item.object_id,
                data_type=item.data_type,
                producer_call_id=item.producer_call_id,
                parent_object_ids=item.parent_object_ids,
                source_resource_digest=(
                    digest_payload(item.source_resource) if item.source_resource else None
                ),
            )
            for item in state.sensitive_objects.values()
        ],
        sequence_progress=[
            SequenceProgressView(
                rule_id=item.rule_id,
                next_step=item.next_step,
                matched_call_ids=item.matched_call_ids,
                matched_object_ids=item.matched_object_ids,
                started_at=item.started_at,
                updated_at=item.updated_at,
            )
            for paths in state.sequence_progress.values()
            for item in paths
        ],
    )
