from __future__ import annotations

from dataclasses import dataclass

from agentgate.adapters import (
    FunctionToolAdapter,
    LangGraphAdapter,
    McpGateway,
    OpenAIAgentsAdapter,
)
from agentgate.capabilities import ToolCapability
from agentgate.events import DataType, ResourceType, SecurityOperation
from agentgate.policy import DecisionAction
from agentgate.runtime import RuntimeContext


async def test_function_adapter_registers_and_executes_only_through_runtime(
    runtime_factory,
) -> None:
    harness = runtime_factory()
    adapter = FunctionToolAdapter(harness.runtime)

    async def read(arguments):
        return {"value": arguments["id"]}

    await adapter.register(
        name="record.read",
        executor=read,
        capability=ToolCapability(
            tool_name="record.read",
            possible_operations=[SecurityOperation.READ],
            resource_type=ResourceType.DATABASE,
            resource_arg="id",
            sensitive_output_types={DataType.INTERNAL},
        ),
    )
    outcome = await adapter.invoke(
        tool_name="record.read",
        arguments={"id": "R1"},
        context=RuntimeContext(principal="analyst", session_id="function"),
    )
    state = await harness.runtime.state_manager.get("analyst", "function")

    assert outcome.decision.action == DecisionAction.ALLOW
    assert outcome.state_updated
    assert state.counters["records_read"] == 1


async def test_langgraph_and_openai_wrappers_share_the_same_runtime(runtime_factory) -> None:
    harness = runtime_factory()
    functions = FunctionToolAdapter(harness.runtime)

    async def read(arguments):
        return {"value": arguments["value"]}

    await functions.register(
        name="value.read",
        executor=read,
        capability=ToolCapability(
            tool_name="value.read",
            possible_operations=[SecurityOperation.READ],
            sensitive_output_types={DataType.PUBLIC},
        ),
    )

    @dataclass
    class Context:
        principal: str
        session_id: str

    def provide(value: Context) -> RuntimeContext:
        return RuntimeContext(principal=value.principal, session_id=value.session_id)

    graph = LangGraphAdapter(functions, provide).wrap("value.read")
    agents = OpenAIAgentsAdapter(functions, provide).wrap("value.read")
    graph_outcome = await graph({"value": "graph"}, Context("user", "shared"))
    agents_outcome = await agents(Context("user", "shared"), {"value": "agents"})
    state = await harness.runtime.state_manager.get("user", "shared")

    assert graph_outcome.state_updated and agents_outcome.state_updated
    assert state.counters["records_read"] == 2


class FakeMcpServer:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []

    async def list_tools(self):
        return [
            {
                "name": "customer_read",
                "description": "Read one database customer record.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"id": {"type": "string"}},
                },
            }
        ]

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return {"id": arguments["id"], "name": "Alice"}


async def test_mcp_gateway_intercepts_tools_call_and_forwards_only_after_runtime(
    runtime_factory,
) -> None:
    harness = runtime_factory()
    upstream = FakeMcpServer()
    gateway = McpGateway(harness.runtime, upstream, server_name="crm")
    capabilities = await gateway.initialize()
    outcome = await gateway.call(
        {
            "jsonrpc": "2.0",
            "id": "mcp-call-1",
            "method": "tools/call",
            "params": {"name": "customer_read", "arguments": {"id": "C1"}},
        },
        RuntimeContext(principal="support", session_id="mcp"),
    )

    assert capabilities[0].tool_name == "crm.customer_read"
    assert outcome.request_event.call_id == "mcp-call-1"
    assert upstream.calls == [("customer_read", {"id": "C1"})]
    assert outcome.state_updated
