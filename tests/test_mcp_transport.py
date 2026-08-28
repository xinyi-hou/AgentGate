from __future__ import annotations

from agentgate.adapters.mcp_transport import (
    McpJsonRpcUpstream,
    McpProtocolProxy,
    static_context_provider,
)
from agentgate.runtime import RuntimeContext


class FakeJsonRpcTransport:
    def __init__(self) -> None:
        self.notifications: list[dict] = []
        self.tool_calls: list[dict] = []

    async def request(self, message):
        method = message["method"]
        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake", "version": "1"},
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {
                "tools": [
                    {
                        "name": "record_read",
                        "description": "Read one database record.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"id": {"type": "string"}},
                        },
                    }
                ]
            }
        elif method == "tools/call":
            self.tool_calls.append(message["params"])
            result = {"content": [{"type": "text", "text": "record-value"}]}
        else:
            raise AssertionError(method)
        return {"jsonrpc": "2.0", "id": message["id"], "result": result}

    async def notify(self, message):
        self.notifications.append(message)


async def test_mcp_protocol_proxy_passes_protocol_methods_and_mediates_tool_calls(
    runtime_factory,
) -> None:
    harness = runtime_factory()
    transport = FakeJsonRpcTransport()
    proxy = McpProtocolProxy(
        harness.runtime,
        McpJsonRpcUpstream(transport),
        context_provider=static_context_provider(
            RuntimeContext(principal="codex", session_id="mcp-session")
        ),
    )

    initialized = await proxy.handle(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    )
    notification = await proxy.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
    listed = await proxy.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    called = await proxy.handle(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "record_read", "arguments": {"id": "R1"}},
        }
    )
    pinged = await proxy.handle({"jsonrpc": "2.0", "id": 4, "method": "ping"})

    assert initialized["result"]["serverInfo"]["name"] == "fake"
    assert notification is None
    assert listed["result"]["tools"][0]["name"] == "record_read"
    assert called["result"]["content"][0]["text"] == "record-value"
    assert pinged["result"] == {}
    assert transport.notifications[0]["method"] == "notifications/initialized"
    assert transport.tool_calls == [{"name": "record_read", "arguments": {"id": "R1"}}]
