from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from agentgate.config import AgentGateSettings
from agentgate.models import GatewayOutcome, IntegrityResult, TaskContract, ToolCall, ToolSpec
from agentgate.runtime.gateway import AgentGate
from agentgate.tools import build_default_registry


class RegistrationRequest(BaseModel):
    spec: ToolSpec


class CallRequest(BaseModel):
    call: ToolCall
    contract: TaskContract


registry, backend = build_default_registry()
gateway = AgentGate.create(AgentGateSettings.from_env(), registry)


@asynccontextmanager
async def lifespan(_: FastAPI):
    await gateway.initialize()
    yield


app = FastAPI(title="AgentGate", version="0.1.0", lifespan=lifespan)


@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "tools": len(registry),
        "policy_backend": gateway.settings.policy_backend,
        "llm_enabled": gateway.settings.llm_enabled,
    }


@app.get("/v1/tools")
async def list_tools() -> list[ToolSpec]:
    return registry.specs()


@app.post("/v1/tools/inspect", response_model=IntegrityResult)
async def inspect_tool(request: RegistrationRequest) -> IntegrityResult:
    return await gateway.inspect_tool(request.spec)


@app.post("/v1/calls/evaluate", response_model=GatewayOutcome)
async def evaluate_call(request: CallRequest) -> GatewayOutcome:
    try:
        decision, modules = await gateway.evaluate_call(request.call, request.contract)
        return GatewayOutcome(
            decision=decision, call=request.call, module_decisions=modules
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/v1/calls/execute", response_model=GatewayOutcome)
async def execute_call(request: CallRequest) -> GatewayOutcome:
    try:
        return await gateway.execute(request.call, request.contract)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/v1/backend/state")
async def backend_state() -> dict[str, Any]:
    return backend.snapshot()
