# AgentGate

AgentGate is a research prototype for stateful runtime detection at the structured agent tool-call
boundary. It normalizes framework-specific calls into security events, correlates the current event
with executed session facts, makes an enforcement decision before side effects occur, and updates
state only from the actual tool result.

```text
Raw Tool Call
   -> Tool-call Security Event Abstraction
   -> ToolSecurityEvent (REQUEST)
   -> Stateful Risk Detection and Runtime Control
   -> Tool Result
   -> ToolSecurityEvent (RESULT)
   -> Session State and Provenance Update
```

The design deliberately adapts established runtime-security mechanisms instead of introducing an
independent terminology:

| AgentGate mechanism | Security-system basis |
| --- | --- |
| Unified runtime gateway | Reference Monitor and complete mediation |
| `event_rules` | Falco/Tetragon-style event-condition-action rules |
| `StateLabel` and `state_rules` | flowbits-style durable state flags |
| `sequence_rules` | EQL/CEP ordered event matching |
| `SensitiveObject` and fingerprints | IFC, taint tracking, and DLP |
| Parent object lineage | Provenance-based intrusion detection |
| `aggregate_rules` | SIEM event-time windows, counts, and thresholds |

The current architecture and research claims are documented in
[research-architecture.md](docs/research-architecture.md). The larger implementation specification
and design plan are retained as background material, but the research architecture describes the
current code.

For a field-level description of the three security modules, supported agent and tool-call forms,
deployment options, and end-to-end examples, see the Chinese
[current implementation guide](docs/current-implementation-guide.zh-CN.md).

## Boundaries

- `ToolCallSecurityEventAbstraction`, `events`, and `capabilities` implement module 1 and only
  normalize calls, results, and security facts.
- `StateManager` and `state` implement module 2. They update labels, counters, provenance objects,
  bounded history, and incremental sequence progress only from executed RESULT events.
- `StatefulRiskControl`, `detection`, and `enforcement` implement module 3. They evaluate REQUEST
  events against prior facts and enforce one of five monotonic actions.
- `runtime` is the Reference Monitor used by every supported adapter.

AgentGate is not a production identity gateway, syscall monitor, full dynamic taint engine, or LLM
trace collector. Its intended use is controlled experiments and agent runtime-security research.

The three core modules are tool-call security event abstraction, session state/provenance
maintenance, and stateful risk detection/runtime control. Deterministic content findings and task
contracts remain supporting inputs to those modules rather than independent architecture layers.
Tool security profiles are generated automatically from names, descriptions, input/output schemas,
and MCP metadata; explicit profiles are needed when those facts are ambiguous.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
make lint
make test
make policy-check
```

Run the research sidecar:

```bash
.venv/bin/agentgate serve --host 127.0.0.1 --port 8080
```

Main endpoints:

```text
POST /v1/tools/register
POST /v1/calls/evaluate
POST /v1/calls/execute
GET  /v1/sessions/{session_id}/state?principal=...
GET  /v1/sessions/{session_id}/events?principal=...
GET  /v1/policies
GET  /v1/audit
POST /v1/approvals
POST /v1/approvals/{id}/approve
POST /v1/approvals/{id}/deny
```

`/v1/calls/evaluate` has no tool side effect and does not update fact state. A capability registered
without an executor is evaluation-only.

## In-Process Example

```python
from agentgate.adapters import FunctionToolAdapter
from agentgate.authorization import TaskContractCompiler
from agentgate.capabilities import ToolCapability
from agentgate.events import ResourceType, SecurityOperation
from agentgate.runtime import RuntimeContext, build_runtime

runtime = build_runtime()
tools = FunctionToolAdapter(runtime)
contract = TaskContractCompiler().compile(
    "Read the latest 2 reports",
    principal="analyst",
    task_id="task-1",
)


async def read_report(arguments):
    return {"path": arguments["path"], "content": "example"}


await tools.register(
    name="report.read",
    executor=read_report,
    capability=ToolCapability(
        tool_name="report.read",
        possible_operations=[SecurityOperation.READ],
        resource_type=ResourceType.FILE,
        resource_arg="path",
    ),
)

outcome = await tools.invoke(
    tool_name="report.read",
    arguments={"path": "/reports/summary"},
    context=RuntimeContext(
        principal="analyst",
        session_id="experiment-1",
        task_id="task-1",
        task_contract=contract.model_dump(mode="json"),
    ),
)
```

The default state backend is memory. Redis can be selected for multi-process experiments. Audit
output supports JSONL and SQLite and stores digests instead of raw arguments and results by default.
Generated experiment outputs and external benchmark checkouts are intentionally excluded from this
repository.

See [evaluation/README.md](evaluation/README.md) for pinned benchmark retrieval, executable
baselines, and report generation.
