from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import AnyHttpUrl, BaseModel, Field, model_validator

from agentgate.adapters.sidecar import RemoteHttpExecutor
from agentgate.api.dependencies import get_runtime
from agentgate.capabilities.models import ToolCapability
from agentgate.runtime.gateway import AgentGateRuntime

router = APIRouter(prefix="/v1/tools", tags=["tools"])


class RemoteToolEndpoint(BaseModel):
    url: AnyHttpUrl
    timeout_seconds: float = Field(default=30.0, gt=0, le=300)


class ToolRegistrationRequest(BaseModel):
    capability: ToolCapability | None = None
    name: str | None = None
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output_schema: dict[str, Any] = Field(default_factory=dict)
    annotations: dict[str, Any] = Field(default_factory=dict)
    remote: RemoteToolEndpoint | None = None
    replace: bool = False

    @model_validator(mode="after")
    def validate_declaration(self) -> ToolRegistrationRequest:
        if self.capability is None and not self.name:
            raise ValueError("either capability or name is required")
        return self


@router.post("/register", response_model=ToolCapability)
async def register_tool(
    request: ToolRegistrationRequest,
    runtime: Annotated[AgentGateRuntime, Depends(get_runtime)],
) -> ToolCapability:
    if request.capability is not None:
        capability = request.capability
    else:
        try:
            capability = await runtime.capability_inferer.infer(
                name=str(request.name),
                description=request.description,
                input_schema=request.input_schema,
                output_schema=request.output_schema,
                annotations=request.annotations,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    executor = (
        RemoteHttpExecutor(str(request.remote.url), timeout_seconds=request.remote.timeout_seconds)
        if request.remote is not None
        else None
    )
    runtime.registry.register(capability, executor, replace=request.replace)
    return capability


@router.get("", response_model=list[ToolCapability])
async def list_tools(
    runtime: Annotated[AgentGateRuntime, Depends(get_runtime)],
) -> list[ToolCapability]:
    return runtime.registry.capabilities()


@router.get("/{tool_name}/capability", response_model=ToolCapability)
@router.get("/{tool_name}/semantic-profile", response_model=ToolCapability)
async def get_tool_capability(
    tool_name: str,
    runtime: Annotated[AgentGateRuntime, Depends(get_runtime)],
) -> ToolCapability:
    return runtime.registry.get(tool_name).capability
