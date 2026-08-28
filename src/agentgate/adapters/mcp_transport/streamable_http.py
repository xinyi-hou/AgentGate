from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from .proxy import McpProtocolProxy
from .upstream import JsonObject


class StreamableHttpJsonRpcUpstream:
    def __init__(self, url: str, *, timeout_seconds: float = 60.0):
        self.url = url
        self.client = httpx.AsyncClient(timeout=timeout_seconds)
        self.session_id: str | None = None
        self.protocol_version: str | None = None

    async def request(self, message: JsonObject) -> JsonObject | None:
        headers = {
            "accept": "application/json, text/event-stream",
            "content-type": "application/json",
        }
        if self.session_id is not None:
            headers["mcp-session-id"] = self.session_id
        if self.protocol_version is not None:
            headers["mcp-protocol-version"] = self.protocol_version
        response = await self.client.post(self.url, json=message, headers=headers)
        response.raise_for_status()
        if value := response.headers.get("mcp-session-id"):
            self.session_id = value
        if message.get("method") == "initialize":
            self.protocol_version = str((message.get("params") or {}).get("protocolVersion", ""))
        if response.status_code == 202 or not response.content:
            return None
        if "text/event-stream" in response.headers.get("content-type", ""):
            return _parse_sse(response.text)
        return response.json()

    async def notify(self, message: JsonObject) -> None:
        await self.request(message)

    async def aclose(self) -> None:
        await self.client.aclose()


def create_streamable_http_proxy_app(proxy: McpProtocolProxy) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            await proxy.upstream.aclose()
            await proxy.runtime.aclose()

    app = FastAPI(title="AgentGate MCP Gateway", lifespan=lifespan)

    @app.post("/mcp")
    async def handle(request: Request) -> Response:
        message = await request.json()
        headers = {key.lower(): value for key, value in request.headers.items()}
        response = await proxy.handle(message, headers)
        if response is None:
            return Response(status_code=202)
        return JSONResponse(response)

    return app


def _parse_sse(payload: str) -> JsonObject | None:
    for line in payload.splitlines():
        if line.startswith("data:"):
            data: Any = json.loads(line[5:].strip())
            if isinstance(data, dict):
                return data
    return None
