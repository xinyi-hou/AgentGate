# AgentGate

AgentGate is a stateful runtime security gateway for mediated structured tool calls. It is a
research prototype for studying whether security facts, lightweight provenance, event sequences,
and cumulative behavior can stop multi-step agent attacks before a tool produces side effects.

```text
Framework / MCP / Sidecar call
  -> CanonicalToolCall
  -> ToolSecurityEvent(REQUEST)
  -> Candidate Agent Transition Graph + trusted TaskAuthorization
  -> ALLOW / AUDIT / RESTRICT / REQUIRE_APPROVAL / BLOCK
  -> Tool execution
  -> ToolSecurityEvent(RESULT)
  -> commit Agent Transition Graph delta
```

AgentGate adapts established runtime-security mechanisms to the structured tool boundary:

| AgentGate mechanism | Security-system basis |
| --- | --- |
| Mediated runtime gateway | Reference Monitor and complete mediation |
| Event rules | Falco/Tetragon event-condition-action |
| Data-object labels | IFC, taint tracking, DLP, and flowbits-style flags |
| ATG paths and `NEXT` edges | EQL/CEP ordered matching |
| `PRODUCES/CONSUMES/DERIVES_FROM` | Provenance-based intrusion detection |
| Aggregate rules | SIEM windows, counts, and thresholds |

## Three Modules

1. `semantics`, `capabilities`, `events`, and `adapters` convert heterogeneous requests into
   `CanonicalToolCall`, then instantiate framework-neutral `ToolSecurityEvent` facts. Deterministic
   extraction runs first; optional schema-constrained LLM resolvers handle ambiguous facts only.
2. `graph`, `labels`, and `provenance` incrementally construct one Agent Transition Graph (ATG) for
   single-agent, multi-tool, and multi-agent execution. It contains Agent, ToolEvent, Resource,
   DataObject, and TrustDomain nodes plus explicit temporal, execution, and value-flow edges.
3. `detection`, `authorization`, and `enforcement` evaluate a noncommitted request extension over
   the ATG. Only an executed RESULT is committed; labels and provenance paths support real-time
   sink checks before SEND, EXECUTE, AUTH, INSTALL, and other high-impact operations.

The normalized operation vocabulary is:

```text
READ WRITE SEND EXECUTE DELETE AUTH PRIVILEGE INSTALL
```

## Security Invariants

- Detection occurs before execution for every call routed through `execute` or the MCP gateway.
- BLOCK and pending approval never enter the committed ATG. Failed calls may create a FAILED
  ToolEvent for audit, but no resource, destination, data, or successful-effect relation.
- RESTRICT is shrink-only; AgentGate rebuilds the REQUEST event and detects it again.
- Caller input cannot clear untrusted state. Trust comes from `RuntimeContext`, tool capability,
  actual result trust domain, and scanner findings.
- An agent request cannot upload its own authorization. AgentGate looks up `TaskAuthorization` in
  a trusted `AuthorizationStore` by `(principal, task_id)`.
- A per-session coordinator covers evaluation, tool execution, and graph commit. Memory mode is
  correct within one runtime; Redis mode uses a cross-instance lock and Redis graph/state stores.
- `/v1/calls/evaluate` is explicitly advisory-only and provides no mediation guarantee.

## Scope

The complete-mediation claim applies only to tool calls routed through AgentGate. AgentGate does
not intercept unmediated shell, network, filesystem, subprocess, direct SDK, or OS syscall access.
It also does not collect prompts, chain-of-thought, model token traces, full OpenTelemetry traces,
or browser/computer-use actions. Provenance is high-confidence tool-boundary value linkage, not
complete language-level dynamic taint.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
make lint
make test
make policy-check
```

Run the HTTP research sidecar:

```bash
.venv/bin/agentgate serve --host 127.0.0.1 --port 8080
```

Main research endpoints:

```text
POST /v1/tools/register
GET  /v1/tools/{tool_name}/capability
POST /v1/calls/evaluate              # advisory_only=true
POST /v1/calls/execute
GET  /v1/sessions/{session_id}/state?principal=...
GET  /v1/sessions/{session_id}/events?principal=...
GET  /v1/sessions/{session_id}/graph?principal=...       # research debug only
GET  /v1/sessions/{session_id}/rule-state?principal=...  # research debug only
GET  /v1/decisions/{decision_id}/evidence                # research debug only
GET  /v1/policies
GET  /v1/audit
POST /v1/approvals/{id}/approve
POST /v1/approvals/{id}/deny
```

Set `AGENTGATE_RESEARCH_DEBUG=true` to expose graph/evidence and compatibility rule state. Content
analysis is observe-only by default; `AGENTGATE_CONTENT_MODE=sanitize` enables the optional
rewriting experiment.

## In-Process Use

```python
from agentgate.adapters import FunctionToolAdapter
from agentgate.authorization import TaskAuthorizationCompiler, TaskIntent
from agentgate.capabilities import ToolCapability
from agentgate.events import ResourceType, SecurityOperation
from agentgate.runtime import RuntimeContext, build_runtime

runtime = build_runtime()
tools = FunctionToolAdapter(runtime)

intent = TaskIntent(task_id="task-1", goal="Read the latest 2 reports")
authorization = TaskAuthorizationCompiler().compile(
    intent,
    principal="analyst",
    entitlements={
        "operations": ["READ"],
        "resources": ["*"],
        "effects": [],
        "destinations": [],
        "max_records": 2,
    },
    issuer="trusted-orchestrator",
)
await runtime.authorization_store.put(authorization)


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
        authorization_id=authorization.authorization_id,
    ),
)
```

## MCP Gateway

STDIO gateway, suitable for Codex and other MCP clients that launch a command:

```bash
.venv/bin/agentgate mcp-stdio \
  --principal codex-user \
  --session-id research-session \
  --task-id task-1 \
  -- your-upstream-mcp-server --stdio
```

Streamable HTTP gateway in front of an upstream MCP endpoint:

```bash
.venv/bin/agentgate mcp-http \
  --principal agent-user \
  --session-id research-session \
  --upstream-url http://127.0.0.1:9000/mcp \
  --port 8081
```

The proxy supports `initialize`, `notifications/initialized`, `tools/list`, `tools/call`, and
`ping`; other JSON-RPC methods are passed through. `tools/list` automatically infers and registers
capabilities. Only `tools/call` is security mediated.

The detailed Chinese implementation guide is
[current-implementation-guide.zh-CN.md](docs/current-implementation-guide.zh-CN.md). The research
claims and invariants are summarized in [research-architecture.md](docs/research-architecture.md).
