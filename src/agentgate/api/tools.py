from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import AnyHttpUrl, BaseModel, Field

from agentgate.adapters.sidecar import RemoteHttpExecutor
from agentgate.api.dependencies import get_runtime
from agentgate.capabilities.models import ToolCapability
from agentgate.runtime.gateway import AgentGateRuntime

router = APIRouter(prefix="/v1/tools", tags=["tools"])


class RemoteToolEndpoint(BaseModel):
    url: AnyHttpUrl
    timeout_seconds: float = Field(default=30.0, gt=0, le=300)


class ToolRegistrationRequest(BaseModel):
    capability: ToolCapability
    remote: RemoteToolEndpoint | None = None
    replace: bool = False


@router.post("/register", response_model=ToolCapability)
async def register_tool(
    request: ToolRegistrationRequest,
    runtime: Annotated[AgentGateRuntime, Depends(get_runtime)],
) -> ToolCapability:
    executor = (
        RemoteHttpExecutor(str(request.remote.url), timeout_seconds=request.remote.timeout_seconds)
        if request.remote is not None
        else None
    )
    runtime.registry.register(request.capability, executor, replace=request.replace)
    return request.capability


@router.get("", response_model=list[ToolCapability])
async def list_tools(
    runtime: Annotated[AgentGateRuntime, Depends(get_runtime)],
) -> list[ToolCapability]:
    return runtime.registry.capabilities()
