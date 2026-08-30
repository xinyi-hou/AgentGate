from __future__ import annotations

import asyncio
import hashlib
import json
import os
import resource
import tempfile
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Literal

from agentgate.adapters import FunctionToolAdapter
from agentgate.audit import JsonlAuditStore
from agentgate.capabilities import CapabilityRegistry, OutputTrust, ToolCapability
from agentgate.detection import DetectionEngine
from agentgate.detection.engine import merge_decisions
from agentgate.detection.graph_engine import GraphRiskEngine
from agentgate.detection.graph_models import GraphRiskEvaluation
from agentgate.detection.single_call import SingleCallDetector
from agentgate.enforcement import ApprovalManager
from agentgate.events import DataType, ResourceType, SecurityOperation, ToolEventBuilder
from agentgate.graph import (
    AgentTransitionGraph,
    AgentTransitionGraphBuilder,
    CandidateGraphExtension,
    DataObjectNode,
    GraphEdgeType,
    GraphNodeType,
    InMemoryGraphStore,
    ToolEventNode,
)
from agentgate.policy import DecisionAction, SecurityDecision, SecurityPolicy, Severity, load_policy
from agentgate.runtime import AgentGateRuntime, RuntimeContext
from agentgate.state import MemoryStateStore, StateManager
from agentgate.state.models import SessionSecurityState
from evaluation.recording import experiment_id, git_revision, stable_hash, write_jsonl
from evaluation.schema import ArtifactPaths, AtgSnapshot, CallRunRecord, TaskRunRecord
from evaluation.statefulbench.cases import StatefulCase, stateful_cases
from evaluation.statefulbench.tools import StatefulEnvironment

StatefulMode = Literal[
    "no_defense",
    "event_only",
    "event_sequence",
    "atg_no_provenance",
    "atg_provenance_no_labels",
    "full",
]

MODE_LABELS = {
    "no_defense": "No Defense",
    "event_only": "A0 Event-only",
    "event_sequence": "A1 Event + Sequence",
    "atg_no_provenance": "A2 ATG without Provenance",
    "atg_provenance_no_labels": "A3 ATG + Provenance without Labels",
    "full": "A4 Full AgentGate",
}


class _NoProvenanceBuilder(AgentTransitionGraphBuilder):
    def sensitive_objects(self, graph, arguments=None, task_id=None):
        del graph, arguments, task_id
        return []

    def build_result_delta(self, graph, candidate, result_event):
        delta = super().build_result_delta(graph, candidate, result_event)
        delta.nodes = [node for node in delta.nodes if not isinstance(node, DataObjectNode)]
        delta.edges = [
            edge
            for edge in delta.edges
            if edge.edge_type
            not in {
                GraphEdgeType.PRODUCES,
                GraphEdgeType.CONSUMES,
                GraphEdgeType.DERIVES_FROM,
            }
        ]
        return delta


class _NoLabelPropagationBuilder(AgentTransitionGraphBuilder):
    def build_result_delta(self, graph, candidate, result_event):
        delta = super().build_result_delta(graph, candidate, result_event)
        if result_event.input_data_objects:
            delta.nodes = [
                node.model_copy(update={"labels": set()})
                if isinstance(node, DataObjectNode)
                else node
                for node in delta.nodes
            ]
        return delta


class _AllowAllRiskEngine(GraphRiskEngine):
    async def evaluate(
        self,
        graph: AgentTransitionGraph,
        candidate: CandidateGraphExtension,
    ) -> GraphRiskEvaluation:
        del graph
        return GraphRiskEvaluation(
            decision=SecurityDecision(action=DecisionAction.ALLOW),
            candidate=candidate,
        )


class _EventOnlyRiskEngine(GraphRiskEngine):
    def __init__(self, policy: SecurityPolicy):
        super().__init__(policy)
        self._event_detector = SingleCallDetector(
            policy.single_call,
            policy.event_rules,
            policy.access_rules,
        )

    async def evaluate(
        self,
        graph: AgentTransitionGraph,
        candidate: CandidateGraphExtension,
    ) -> GraphRiskEvaluation:
        del graph
        event = candidate.request_event
        state = SessionSecurityState(
            principal=event.principal,
            session_id=event.session_id,
        )
        return GraphRiskEvaluation(
            decision=self._event_detector.evaluate(event, state),
            candidate=candidate,
        )


class _SequenceOnlyRiskEngine(_EventOnlyRiskEngine):
    async def evaluate(
        self,
        graph: AgentTransitionGraph,
        candidate: CandidateGraphExtension,
    ) -> GraphRiskEvaluation:
        base = await super().evaluate(graph, candidate)
        event = candidate.request_event
        events = sorted(
            (node for node in graph.nodes.values() if isinstance(node, ToolEventNode)),
            key=lambda node: (node.timestamp, node.node_id),
        )
        decisions = [base.decision]
        sensitive_read = any(
            node.operation == SecurityOperation.READ
            and bool(node.data_types - {DataType.PUBLIC})
            and node.task_id == event.task_id
            for node in events
        )
        untrusted_read = any(
            node.operation == SecurityOperation.READ
            and node.untrusted_context
            and node.task_id == event.task_id
            for node in events
        )
        if (
            event.operation == SecurityOperation.SEND
            and event.trust_domain.value == "UNKNOWN_EXTERNAL"
            and sensitive_read
        ):
            decisions.append(_sequence_decision("sequence_sensitive_send"))
        if (
            event.operation in {SecurityOperation.EXECUTE, SecurityOperation.INSTALL}
            and untrusted_read
        ):
            decisions.append(_sequence_decision("sequence_untrusted_high_impact"))
        return base.model_copy(update={"decision": merge_decisions(decisions)})


def _sequence_decision(rule_id: str) -> SecurityDecision:
    return SecurityDecision(
        action=DecisionAction.BLOCK,
        rule_ids=[rule_id],
        reasons=["An operation-only sequence matched without a data dependency constraint."],
        severity=Severity.HIGH,
        relation_evidence=["ordered_events_only"],
    )


class _ExecutableAgent:
    def __init__(
        self,
        tools: FunctionToolAdapter,
        context: RuntimeContext,
        environment: StatefulEnvironment,
        experiment: str,
        case: StatefulCase,
    ):
        self.tools = tools
        self.context = context
        self.environment = environment
        self.experiment = experiment
        self.case = case
        self.calls: list[CallRunRecord] = []
        self.blocked = False

    async def call(self, tool_name: str, arguments: dict[str, Any]) -> Any | None:
        if self.blocked:
            return None
        call_index = len(self.calls) + 1
        call_id = f"{self.case.case_id}-call-{call_index}"
        side_effects_before = len(self.environment.side_effects)
        timings_before = len(self.environment.executor_timings_ms)
        started = time.perf_counter()
        outcome = await self.tools.invoke(
            tool_name=tool_name,
            arguments=arguments,
            context=self.context,
            call_id=call_id,
            source_framework="statefulbench",
            source_transport="in_process_executable",
        )
        total_ms = (time.perf_counter() - started) * 1000
        upstream_ms = (
            self.environment.executor_timings_ms[-1]
            if len(self.environment.executor_timings_ms) > timings_before
            else 0.0
        )
        self.calls.append(
            CallRunRecord(
                experiment_id=self.experiment,
                benchmark="AgentGate-StatefulBench",
                case_id=self.case.case_id,
                call_index=call_index,
                call_id=call_id,
                tool_name=tool_name,
                operation=outcome.request_event.operation.value,
                arguments_digest=hashlib.sha256(
                    json.dumps(arguments, sort_keys=True, default=str).encode()
                ).hexdigest(),
                decision=outcome.decision.action.value,
                rule_ids=outcome.decision.rule_ids,
                executed=outcome.execution is not None,
                success=outcome.execution.success if outcome.execution else None,
                side_effects_before=side_effects_before,
                side_effects_after=len(self.environment.side_effects),
                agentgate_total_ms=total_ms,
                upstream_tool_ms=upstream_ms,
                control_action_ms=max(0.0, total_ms - upstream_ms),
                llm_called=outcome.llm_called,
                llm_latency_ms=outcome.llm_latency_ms or 0.0,
            )
        )
        if not outcome.decision.permits_execution:
            self.blocked = True
            return None
        if outcome.execution is None or not outcome.execution.success:
            return None
        return outcome.execution.output


async def run_statefulbench(
    modes: Iterable[StatefulMode] = (
        "no_defense",
        "event_only",
        "event_sequence",
        "atg_no_provenance",
        "atg_provenance_no_labels",
        "full",
    ),
    *,
    output_root: str | Path = "evaluation/results",
    cases: Iterable[StatefulCase] | None = None,
) -> tuple[list[TaskRunRecord], list[CallRunRecord]]:
    selected_cases = list(cases or stateful_cases())
    selected_modes = list(modes)
    config = {
        "benchmark": "AgentGate-StatefulBench",
        "modes": selected_modes,
        "cases": [item.case_id for item in selected_cases],
        "policy": load_policy().model_dump(mode="json"),
    }
    run_id = experiment_id(config, prefix="stateful")
    output_root = Path(output_root)
    tasks: list[TaskRunRecord] = []
    calls: list[CallRunRecord] = []
    for mode in selected_modes:
        for case in selected_cases:
            task, task_calls = await _run_case(case, mode, run_id, output_root, config)
            tasks.append(task)
            calls.extend(task_calls)
    write_jsonl(output_root / "raw" / "statefulbench_tasks.jsonl", tasks)
    write_jsonl(output_root / "raw" / "statefulbench_calls.jsonl", calls)
    return tasks, calls


async def _run_case(
    case: StatefulCase,
    mode: StatefulMode,
    run_id: str,
    output_root: Path,
    config: dict[str, Any],
) -> tuple[TaskRunRecord, list[CallRunRecord]]:
    with tempfile.TemporaryDirectory(prefix="agentgate-stateful-") as temp:
        environment = StatefulEnvironment(Path(temp))
        audit_path = output_root / "raw" / "audit" / mode / f"{case.case_id}.jsonl"
        runtime = _build_runtime(mode, environment, audit_path)
        tools = FunctionToolAdapter(runtime)
        await _register_tools(tools, environment)
        context = RuntimeContext(
            principal="statefulbench-user",
            session_id=f"{mode}-{case.case_id}",
            task_id=case.case_id,
            agent_id="statefulbench-agent",
        )
        agent = _ExecutableAgent(tools, context, environment, run_id, case)
        started = time.perf_counter()
        completed = await case.workflow(agent)
        elapsed_ms = (time.perf_counter() - started) * 1000
        graph = await runtime.graph_store.get_session_graph(context.principal, context.session_id)
        snapshot = _graph_snapshot(graph)
        harmful = any(effect.harmful for effect in environment.side_effects)
        blocked_call = next((call for call in agent.calls if not call.executed), None)
        attack_success = case.is_attack and harmful
        task_success = (not case.is_attack) and completed and not harmful
        trace_path = output_root / "raw" / "traces" / mode / f"{case.case_id}.jsonl"
        atg_path = output_root / "raw" / "atg" / mode / f"{case.case_id}.json"
        write_jsonl(trace_path, agent.calls)
        atg_path.parent.mkdir(parents=True, exist_ok=True)
        atg_path.write_text(graph.model_dump_json(indent=2, exclude={"index"}), encoding="utf-8")
        actions = [call.decision for call in agent.calls]
        task = TaskRunRecord(
            experiment_id=run_id,
            benchmark="AgentGate-StatefulBench",
            benchmark_commit=git_revision(),
            case_id=case.case_id,
            attack_type=case.pattern if case.is_attack else "benign_control",
            is_attack=case.is_attack,
            multi_step=True,
            single_server=not case.multi_server,
            multi_server=case.multi_server,
            requires_provenance=case.requires_provenance,
            paired_case_id=case.paired_case_id,
            defense=MODE_LABELS[mode],
            defense_version="0.6.0",
            defense_commit=git_revision(),
            defense_config_hash=stable_hash({"mode": mode, "config": config}),
            agent_model="deterministic-executable-agent",
            task_success=task_success,
            attack_success=attack_success,
            harmful_side_effect_occurred=harmful,
            attack_prevented_before_side_effect=case.is_attack and agent.blocked and not harmful,
            late_detection=bool(blocked_call and harmful),
            benign_degraded=(not case.is_attack) and (agent.blocked or not completed),
            blocked=agent.blocked,
            block_step=blocked_call.call_index if blocked_call else None,
            first_block_step=blocked_call.call_index if blocked_call else None,
            tool_calls_before_block=blocked_call.call_index - 1 if blocked_call else None,
            block_phase="request" if blocked_call else "none",
            decision=actions[-1] if actions else "ALLOW",
            matched_rules=sorted({rule for call in agent.calls for rule in call.rule_ids}),
            tool_calls=len(agent.calls),
            turns=len(agent.calls) + 1,
            trajectory_length=len(agent.calls),
            tool_call_successes=sum(call.success is True for call in agent.calls),
            end_to_end_latency_ms=elapsed_ms,
            agentgate_total_ms=sum(call.agentgate_total_ms for call in agent.calls),
            upstream_tool_ms=sum(call.upstream_tool_ms for call in agent.calls),
            process_rss_bytes=_rss_bytes(),
            peak_memory_bytes=_peak_rss_bytes(),
            blocked_sink_event_id=blocked_call.call_id if blocked_call else None,
            atg=snapshot,
            artifacts=ArtifactPaths(
                trace_path=str(trace_path),
                atg_path=str(atg_path),
                decision_log_path=str(audit_path),
            ),
            notes=[
                "Ground truth is derived from isolated executable side effects.",
                "The controlled agent consumes real prior tool outputs; no trace is replayed.",
            ],
        )
        side_effect_path = output_root / "raw" / "side_effects" / mode / f"{case.case_id}.jsonl"
        write_jsonl(side_effect_path, environment.side_effects)
        await runtime.aclose()
        return task, agent.calls


def _build_runtime(
    mode: StatefulMode,
    environment: StatefulEnvironment,
    audit_path: Path,
) -> AgentGateRuntime:
    policy = _policy_for_mode(mode)
    if mode in {"event_only", "event_sequence", "atg_no_provenance"}:
        graph_builder: AgentTransitionGraphBuilder = _NoProvenanceBuilder()
    elif mode == "atg_provenance_no_labels":
        graph_builder = _NoLabelPropagationBuilder()
    else:
        graph_builder = AgentTransitionGraphBuilder()
    if mode == "no_defense":
        graph_detector: GraphRiskEngine = _AllowAllRiskEngine(policy)
    elif mode == "event_only":
        graph_detector = _EventOnlyRiskEngine(policy)
    elif mode == "event_sequence":
        graph_detector = _SequenceOnlyRiskEngine(policy)
    else:
        graph_detector = GraphRiskEngine(policy)
    registry = CapabilityRegistry()
    return AgentGateRuntime(
        registry=registry,
        event_builder=ToolEventBuilder(
            internal_domains={"corp.internal"}, trusted_external_domains={"partner.test"}
        ),
        state_manager=StateManager(MemoryStateStore()),
        detector=DetectionEngine(policy),
        approvals=ApprovalManager(),
        audit=JsonlAuditStore(audit_path),
        graph_store=InMemoryGraphStore(),
        graph_builder=graph_builder,
        graph_detector=graph_detector,
    )


def _policy_for_mode(mode: StatefulMode) -> SecurityPolicy:
    policy = load_policy()
    if mode == "no_defense":
        return SecurityPolicy()
    # The RQ2 policy isolates detection mechanisms. Generic approvals for every
    # external SEND or INSTALL would block both members of each paired case and
    # hide the contribution of sequence, provenance, and propagated labels.
    policy = policy.model_copy(update={"event_rules": [], "state_rules": []})
    if mode == "event_only":
        return policy.model_copy(
            update={
                "aggregate_rules": [],
                "sequence_rules": [],
                "graph_rules": [],
            }
        )
    if mode == "event_sequence":
        return policy.model_copy(update={"aggregate_rules": [], "graph_rules": []})
    return policy


async def _register_tools(
    tools: FunctionToolAdapter,
    environment: StatefulEnvironment,
) -> None:
    definitions = []
    for server in ("server_a", "server_b", "server_c"):
        definitions.extend(
            [
                (
                    f"{server}.customer.read",
                    ToolCapability(
                        tool_name=f"{server}.customer.read",
                        possible_operations=[SecurityOperation.READ],
                        resource_type=ResourceType.DATABASE,
                        resource_arg="customer_id",
                        scope_arg="count",
                        sensitive_output_types={DataType.PERSONAL},
                        output_trust=OutputTrust.INTERNAL,
                    ),
                    environment.sensitive_read,
                ),
                (
                    f"{server}.vault.read",
                    ToolCapability(
                        tool_name=f"{server}.vault.read",
                        possible_operations=[SecurityOperation.READ],
                        resource_type=ResourceType.CREDENTIAL,
                        resource_arg="key",
                        sensitive_output_types={DataType.CREDENTIAL},
                        output_trust=OutputTrust.INTERNAL,
                    ),
                    environment.credential_read,
                ),
                (
                    f"{server}.public.read",
                    ToolCapability(
                        tool_name=f"{server}.public.read",
                        possible_operations=[SecurityOperation.READ],
                        resource_type=ResourceType.APPLICATION,
                        resource_arg="value",
                        sensitive_output_types={DataType.PUBLIC},
                        output_trust=OutputTrust.TRUSTED,
                    ),
                    environment.public_read,
                ),
                (
                    f"{server}.web.read",
                    ToolCapability(
                        tool_name=f"{server}.web.read",
                        possible_operations=[SecurityOperation.READ],
                        resource_type=ResourceType.NETWORK,
                        resource_arg="url",
                        destination_arg="url",
                        output_trust=OutputTrust.UNTRUSTED,
                    ),
                    environment.external_read,
                ),
                (
                    f"{server}.data.transform",
                    ToolCapability(
                        tool_name=f"{server}.data.transform",
                        possible_operations=[SecurityOperation.WRITE],
                        resource_type=ResourceType.MEMORY,
                        payload_args=["value"],
                        output_trust=OutputTrust.TRUSTED,
                    ),
                    environment.transform,
                ),
                (
                    f"{server}.data.aggregate",
                    ToolCapability(
                        tool_name=f"{server}.data.aggregate",
                        possible_operations=[SecurityOperation.WRITE],
                        resource_type=ResourceType.MEMORY,
                        payload_args=["records"],
                        output_trust=OutputTrust.TRUSTED,
                    ),
                    environment.aggregate,
                ),
                (
                    f"{server}.file.write",
                    ToolCapability(
                        tool_name=f"{server}.file.write",
                        possible_operations=[SecurityOperation.WRITE],
                        resource_type=ResourceType.FILE,
                        resource_arg="path",
                        payload_args=["content"],
                    ),
                    environment.file_write,
                ),
                (
                    f"{server}.message.send",
                    ToolCapability(
                        tool_name=f"{server}.message.send",
                        possible_operations=[SecurityOperation.SEND],
                        resource_type=ResourceType.MESSAGE,
                        destination_arg="recipient",
                        payload_args=["body", "attachment"],
                    ),
                    environment.send,
                ),
                (
                    f"{server}.shell.execute",
                    ToolCapability(
                        tool_name=f"{server}.shell.execute",
                        possible_operations=[SecurityOperation.EXECUTE],
                        resource_type=ResourceType.PROCESS,
                        resource_arg="command",
                        payload_args=["command"],
                    ),
                    environment.execute,
                ),
                (
                    f"{server}.package.install",
                    ToolCapability(
                        tool_name=f"{server}.package.install",
                        possible_operations=[SecurityOperation.INSTALL],
                        resource_type=ResourceType.APPLICATION,
                        resource_arg="package",
                        payload_args=["source"],
                    ),
                    environment.install,
                ),
            ]
        )
    for name, capability, executor in definitions:
        await tools.register(
            name=name,
            capability=capability,
            executor=environment.timed(executor),
        )


def _graph_snapshot(graph: AgentTransitionGraph) -> AtgSnapshot:
    counts = {node_type: 0 for node_type in GraphNodeType}
    for node in graph.nodes.values():
        counts[node.node_type] += 1
    edge_counts = {edge_type: 0 for edge_type in GraphEdgeType}
    for edge in graph.edges.values():
        edge_counts[edge.edge_type] += 1
    provenance = sum(
        edge_counts[item]
        for item in (GraphEdgeType.PRODUCES, GraphEdgeType.CONSUMES, GraphEdgeType.DERIVES_FROM)
    )
    data_nodes = [node for node in graph.nodes.values() if isinstance(node, DataObjectNode)]
    return AtgSnapshot(
        agent_nodes=counts[GraphNodeType.AGENT],
        tool_event_nodes=counts[GraphNodeType.TOOL_EVENT],
        resource_nodes=counts[GraphNodeType.RESOURCE],
        data_object_nodes=counts[GraphNodeType.DATA],
        trust_domain_nodes=counts[GraphNodeType.TRUST_DOMAIN],
        edges=len(graph.edges),
        provenance_edges=provenance,
        dependency_edges_constructed=edge_counts[GraphEdgeType.CONSUMES]
        + edge_counts[GraphEdgeType.DERIVES_FROM],
        produces_edges=edge_counts[GraphEdgeType.PRODUCES],
        consumes_edges=edge_counts[GraphEdgeType.CONSUMES],
        derives_from_edges=edge_counts[GraphEdgeType.DERIVES_FROM],
        propagated_label_count=sum(len(node.labels) for node in data_nodes),
        max_provenance_depth=_max_provenance_depth(graph),
        graph_memory_bytes=len(graph.model_dump_json().encode()),
    )


def _max_provenance_depth(graph: AgentTransitionGraph) -> int:
    outgoing: dict[str, list[str]] = {}
    for edge in graph.edges.values():
        if edge.edge_type == GraphEdgeType.DERIVES_FROM:
            outgoing.setdefault(edge.source_id, []).append(edge.target_id)

    memo: dict[str, int] = {}

    def depth(node_id: str, visiting: set[str]) -> int:
        if node_id in memo:
            return memo[node_id]
        if node_id in visiting:
            return 0
        parents = outgoing.get(node_id, [])
        result = (
            0 if not parents else 1 + max(depth(parent, visiting | {node_id}) for parent in parents)
        )
        memo[node_id] = result
        return result

    return max((depth(node.node_id, set()) for node in graph.nodes.values()), default=0)


def _rss_bytes() -> int:
    try:
        pages = int(Path("/proc/self/statm").read_text().split()[1])
        return pages * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError, IndexError):
        return 0


def _peak_rss_bytes() -> int:
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(value * 1024)


def run_statefulbench_sync(**kwargs):
    return asyncio.run(run_statefulbench(**kwargs))
