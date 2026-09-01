from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from agentgate import __version__
from agentgate.api.approvals import router as approvals_router
from agentgate.api.audit import router as audit_router
from agentgate.api.calls import router as calls_router
from agentgate.api.decisions import router as decisions_router
from agentgate.api.policies import router as policies_router
from agentgate.api.sessions import router as sessions_router
from agentgate.api.tools import router as tools_router
from agentgate.runtime.factory import build_runtime
from agentgate.runtime.gateway import AgentGateRuntime


def create_app(runtime: AgentGateRuntime | None = None) -> FastAPI:
    gateway = runtime or build_runtime()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            await gateway.aclose()

    application = FastAPI(title="AgentGate", version=__version__, lifespan=lifespan)
    application.state.agentgate = gateway
    application.include_router(tools_router)
    application.include_router(calls_router)
    application.include_router(decisions_router)
    application.include_router(sessions_router)
    application.include_router(policies_router)
    application.include_router(approvals_router)
    application.include_router(audit_router)

    @application.get("/health")
    async def health() -> dict[str, object]:
        return {
            "status": "ok",
            "registered_tools": len(gateway.registry),
            "sequence_rules": len(gateway.detector.policy.sequence_rules),
            "graph_rules": len(gateway.graph_detector.policy.graph_rules),
            "llm_enabled": gateway.llm_completion is not None,
            "llm_model": gateway.llm_model,
        }

    @application.exception_handler(KeyError)
    async def key_error(_: Request, exc: KeyError) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @application.exception_handler(ValueError)
    async def value_error(_: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @application.exception_handler(RuntimeError)
    async def runtime_error(_: Request, exc: RuntimeError) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    return application


app = create_app()
