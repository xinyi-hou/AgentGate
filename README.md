# AgentGate

AgentGate is a stateful runtime security gateway for structured agent tool calls. It observes only
the tool invocation boundary, converts framework-specific calls into security facts, evaluates the
request against session state and policy, and updates fact state only after the tool returns.

The implementation follows three strict module boundaries:

```text
ToolSecurityEvent  ->  Detection + SecurityDecision  ->  Tool execution
                                                           |
                                                           v
                                                SessionSecurityState
```

- `events` and `capabilities` normalize calls into facts. They never return ALLOW or BLOCK.
- `state` stores executed facts, counters, sensitive objects, provenance, and sensitive history.
  It never makes a security decision.
- `detection`, `policy`, and `enforcement` evaluate requests and apply restrictions, approvals,
  blocking, and isolation. Detection never mutates fact state.
- `runtime` is the only orchestration and execution path used by every adapter.

The authoritative design documents are
[AgentGate_Implementation_Spec.md](docs/AgentGate_Implementation_Spec.md) and
[AgentGate-Plan.md](docs/AgentGate-Plan.md).

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
make lint
make test
```

Run the HTTP sidecar:

```bash
.venv/bin/agentgate serve --host 127.0.0.1 --port 8080
```

The main endpoints are:

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

`/v1/calls/evaluate` has no tool side effect and does not update session fact state.
`/v1/calls/execute` performs the complete REQUEST, decision, execution, RESULT, state update, and
audit flow. A capability registered without a remote endpoint is evaluation-only; in-process
callers register an async executor through `FunctionToolAdapter`.

## Runtime Example

```python
from agentgate.adapters import FunctionToolAdapter
from agentgate.capabilities import ToolCapability
from agentgate.events import ResourceType, SecurityOperation
from agentgate.runtime import RuntimeContext, build_runtime

runtime = build_runtime()
functions = FunctionToolAdapter(runtime)

async def read_report(arguments):
    return {"path": arguments["path"], "content": "example"}

await functions.register(
    name="report.read",
    executor=read_report,
    capability=ToolCapability(
        tool_name="report.read",
        possible_operations=[SecurityOperation.READ],
        resource_type=ResourceType.FILE,
        resource_arg="path",
    ),
)

outcome = await functions.invoke(
    tool_name="report.read",
    arguments={"path": "/reports/summary"},
    context=RuntimeContext(principal="analyst", session_id="task-1"),
)
```

## State And Audit

The memory store is the default. Set `AGENTGATE_REDIS_URL` to use atomic, shared Redis session
state with TTL. Sensitive history is bounded by count and time.

Audit records are written to `.agentgate/security-audit.jsonl` by default. Set
`AGENTGATE_AUDIT_BACKEND=sqlite` and an SQLite audit path to use SQLite. REQUEST arguments, RESULT
values, resource identifiers, and destinations are represented by digests; secrets are
redacted. Raw audit payloads can only be enabled explicitly with
`AGENTGATE_UNSAFE_DEBUG_AUDIT_PAYLOADS=true`.

Validate the active policy with:

```bash
.venv/bin/agentgate policy-check
```
