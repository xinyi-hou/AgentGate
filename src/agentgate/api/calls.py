from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from agentgate.api.dependencies import get_runtime
from agentgate.api.models import SidecarToolCall
from agentgate.runtime.gateway import AgentGateRuntime
from agentgate.runtime.models import RuntimeOutcome

router = APIRouter(tags=["calls"])


@router.post("/v1/calls/evaluate", response_model=RuntimeOutcome)
async def evaluate_call(
    call: SidecarToolCall,
    runtime: Annotated[AgentGateRuntime, Depends(get_runtime)],
) -> RuntimeOutcome:
    return await runtime.evaluate(call.to_canonical_call())


@router.post("/v1/calls/execute", response_model=RuntimeOutcome)
@router.post("/v1/tool/call", response_model=RuntimeOutcome, include_in_schema=False)
async def execute_call(
    call: SidecarToolCall,
    runtime: Annotated[AgentGateRuntime, Depends(get_runtime)],
) -> RuntimeOutcome:
    return await runtime.execute(call.to_canonical_call())
