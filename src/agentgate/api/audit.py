from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from agentgate.api.dependencies import get_runtime
from agentgate.audit.models import AuditRecord
from agentgate.runtime.gateway import AgentGateRuntime

router = APIRouter(prefix="/v1/audit", tags=["audit"])


@router.get("", response_model=list[AuditRecord])
async def query_audit(
    runtime: Annotated[AgentGateRuntime, Depends(get_runtime)],
    principal: Annotated[str | None, Query()] = None,
    session_id: Annotated[str | None, Query()] = None,
) -> list[AuditRecord]:
    return await runtime.audit.query(principal=principal, session_id=session_id)
