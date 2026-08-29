from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from agentgate.api.dependencies import get_runtime
from agentgate.runtime.gateway import AgentGateRuntime

router = APIRouter(prefix="/v1/decisions", tags=["decisions"])


@router.get("/{decision_id}/evidence")
async def get_decision_evidence(
    decision_id: str,
    runtime: Annotated[AgentGateRuntime, Depends(get_runtime)],
) -> dict:
    if not runtime.research_debug:
        raise HTTPException(status_code=404, detail="research debug endpoints are disabled")
    try:
        return runtime.get_decision_evidence(decision_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
