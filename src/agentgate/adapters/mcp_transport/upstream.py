from __future__ import annotations

from typing import Any, Protocol

JsonObject = dict[str, Any]


class JsonRpcUpstream(Protocol):
    async def request(self, message: JsonObject) -> JsonObject | None: ...

    async def notify(self, message: JsonObject) -> None: ...


class McpJsonRpcUpstream:
    """Expose MCP tool helpers over a generic JSON-RPC transport."""

    def __init__(self, transport: JsonRpcUpstream):
        self.transport = transport
        self._next_id = 1

    async def list_tools(self) -> list[JsonObject]:
        response = await self._request("tools/list", {})
        result = response.get("result", {})
        return list(result.get("tools", []))

    async def call_tool(self, name: str, arguments: JsonObject) -> Any:
        response = await self._request(
            "tools/call",
            {"name": name, "arguments": arguments},
        )
        if "error" in response:
            raise McpUpstreamError(response["error"])
        return response.get("result")

    async def forward(self, message: JsonObject) -> JsonObject | None:
        if "id" in message:
            return await self.transport.request(message)
        await self.transport.notify(message)
        return None

    async def aclose(self) -> None:
        close = getattr(self.transport, "aclose", None)
        if close is not None:
            await close()

    async def _request(self, method: str, params: JsonObject) -> JsonObject:
        request_id = self._next_id
        self._next_id += 1
        response = await self.transport.request(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params,
            }
        )
        if response is None:
            raise McpUpstreamError({"code": -32603, "message": "upstream returned no response"})
        return response


class McpUpstreamError(RuntimeError):
    def __init__(self, error: Any):
        super().__init__(str(error))
        self.error = error
