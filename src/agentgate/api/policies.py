from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from agentgate.api.dependencies import get_runtime
from agentgate.policy.models import SecurityPolicy
from agentgate.runtime.gateway import AgentGateRuntime

router = APIRouter(prefix="/v1/policies", tags=["policies"])


@router.get("", response_model=SecurityPolicy)
async def get_policies(
    runtime: Annotated[AgentGateRuntime, Depends(get_runtime)],
) -> SecurityPolicy:
    return runtime.detector.policy
