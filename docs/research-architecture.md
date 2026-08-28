# AgentGate Research Architecture

## 1. Position

AgentGate studies stateful runtime security for structured agent tool calls. The question is
whether facts retained at the tool boundary, lightweight data provenance, ordered event patterns,
and cumulative thresholds can detect multi-step behavior that stateless per-call checks miss.

The implementation is deliberately narrower than an operating-system monitor:

```text
Tool request -> normalized security event -> stateful decision -> tool result
            -> executed fact update -> rule matching state update
```

It does not require prompt, chain-of-thought, token, or full execution traces.

## 2. Adapted Mechanisms

| Source mechanism | AgentGate adaptation | Deliberate omission |
| --- | --- | --- |
| Reference Monitor | One gateway mediates every routed tool execution | No syscall/kernel mediation |
| Falco/Tetragon ECA | Predicates over one normalized REQUEST | No kernel event vocabulary |
| flowbits | Scoped facts set from successful RESULT events | No packet-flow model |
| EQL/CEP | Incremental ordered tool-event automata | No general query language |
| IFC/taint/DLP | Typed objects and digest-based argument linkage | No byte-level taint |
| Provenance IDS | Parent links between derived tool outputs | No whole-system graph |
| SIEM correlation | Event-time windows and projected thresholds | No log analytics platform |

## 3. Module Boundaries

### Module 1: Tool-call security event abstraction

Input: raw framework/MCP call, tool capability, trusted runtime identity, and relevant sensitive
objects. Output: one REQUEST event. After execution, the module consumes the real result and emits
one RESULT event.

It owns operation classification, resource/scope/destination binding, data-object matching, trust
domain classification, output trust classification, and auxiliary content findings. It does not
read policy, update session state, or produce a decision.

### Module 2: Session facts and provenance

Input: successful or failed RESULT event. Output: updated `SessionSecurityState`.

The state contains labels with source/TTL facts, counters, sensitive objects, parent relationships,
and bounded recent security events. It records what actually happened. It contains no `rule_id`,
`next_step`, or automaton progress.

### Module 3: Detection and runtime control

Input: current REQUEST, prior `SessionSecurityState`, independent `RuleMatchState`, policy, and an
optional trusted `TaskAuthorization`. Output: one monotonic decision.

This module owns single-event rules, state-label rules, aggregate rules, sequence automata,
approval, shrink-only rewriting, blocking, and the detection-state stores. A successful RESULT is
observed only after module 2 commits its facts.

## 4. Runtime Invariants

`AgentGateRuntime` enforces:

1. Unknown or executor-less tools fail closed for execution.
2. Detection runs before the executor.
3. BLOCK and pending approval do not update facts or rule progress.
4. Failed execution can increment failure telemetry but does not create successful-effect facts.
5. RESTRICT may only reduce arguments and must be normalized and detected again.
6. Approval is bound to principal, session, call, tool, and rewritten argument digest.
7. REQUEST preview never mutates either state store.
8. Successful RESULT first updates facts and then advances independent detection state.
9. Runtime time, not caller-supplied waiting time, timestamps the mediated REQUEST.
10. One coordinator lock covers the complete stateful execution transaction.

## 5. Event And Capability Model

`ToolSecurityEvent` records identity, operation, resource, scope, data objects/types, destination,
trust domain, effects, trust evidence, success, affected count, and time. REQUEST is proposed
behavior; RESULT is observed behavior.

The operation taxonomy is:

```text
READ WRITE SEND EXECUTE DELETE AUTH PRIVILEGE INSTALL
```

`AUTH` covers login, credential use, token exchange, and identity authentication. `PRIVILEGE`
covers role grants, permission changes, IAM policy changes, and administrator assignment.

`ToolCapability` may be explicit or inferred from name, description, schemas, and untrusted MCP
metadata. Each inferred field carries value, confidence, evidence, and source. Multi-operation
tools require an explicit `operation_arg` and `operation_map`; an unmapped invocation fails closed.
Capability evaluation reports field-level operation, resource, binding, data, and effect accuracy
against a gold set.

`output_trust` is `TRUSTED`, `INTERNAL`, `UNTRUSTED`, or `DYNAMIC`. An untrusted successful output,
an unknown-external dynamic output, or a content finding adds trust evidence and can set
`EXPOSED_TO_UNTRUSTED_CONTENT`. Caller hints can add evidence but cannot remove state.

`ContentScanner` is auxiliary trust evidence extraction. The default `observe` mode preserves tool
output. Optional `sanitize` mode exists as a separate experiment and is not the paper's default.

## 6. Fact State And Scope

Physical session storage is keyed by `(principal, session_id)`. Each label fact, object, and event
also records task and agent scope. Different agents in one task can share data dependencies;
different tasks in one session do not automatically share labels, objects, aggregate history, or
high-confidence sequence matches.

Labels have TTLs and retain source call identifiers. Counters record actual affected counts rather
than only requested maxima. Sensitive objects retain type, source resource/field, producer,
parents, fingerprints, creation time, last-seen time, task, and agent.

## 7. Detection State

`RuleMatchState` is stored separately by `(principal, session_id, policy_version)`. It includes rule
identity, next step, matched call/object identifiers, bounded event summaries, start/update times,
and expiry. Policy versioning prevents paths created under one policy from being interpreted by a
different automaton.

REQUEST evaluation previews whether the current event would complete a path. Only successful
RESULT events advance paths. Therefore rejected attempts and approval requests do not become
historical attack steps.

Sequence constraints include same session, task, agent, resource, object, destination, maximum
interval, and `data_dependency`. The latter means high-confidence lineage overlap, not complete
semantic data-flow equivalence.

## 8. Provenance

A successful sensitive READ creates field-level `SensitiveObject` values when deterministic field
evidence exists. The system stores one-way signatures over normalized values, compact values,
tokens/n-grams, URL-decoded variants, Base64-decoded variants, and supplied digests. Later arguments
are compared using the same representation.

A WRITE that consumes an object creates a child object:

```text
READ -> D1 -> WRITE -> D2 -> SEND/EXECUTE(D2)
```

This distinguishes a real linked exfiltration from “the session once read a secret and later sent
unrelated public text.” It can miss encryption, complex transformations, chunking, semantic
paraphrase, images, and values hidden inside uninstrumented code.

## 9. Trusted Authorization

`TaskIntent(task_id, goal)` describes user intent but grants no authority. A trusted orchestrator or
policy service compiles it against external entitlements into `TaskAuthorization`. Compilation can
only intersect/shrink operation, resource, effect, destination, and record ceilings.

Ordinary calls carry only identity and `task_id`. Runtime retrieves authorization from
`AuthorizationStore`; the sidecar schema rejects uploaded authorization objects. The memory store
is a research control-plane primitive. HMAC signing helpers are available for experiments that
move authorization across a trust boundary.

## 10. Mediation And Deployment

Supported in-process adapters wrap function tools, LangGraph callbacks, and OpenAI Agents-style
functions. The HTTP sidecar supports explicitly registered local/remote executors.

The MCP transport proxy can sit between a real client and server over STDIO or Streamable HTTP. It
passes `initialize`, `notifications/initialized`, `tools/list`, `ping`, and other JSON-RPC methods;
it automatically registers listed tools and mediates `tools/call` through the runtime.

Complete mediation is guaranteed only for calls routed through these boundaries. Raw subprocess,
socket, direct filesystem, direct SDK, or syscall access is outside the model.

Memory stores plus `LocalSessionExecutionCoordinator` support one runtime process. When
`AGENTGATE_REDIS_URL` is configured, fact state, rule state, and the full-pipeline session lock use
Redis for multi-instance research experiments. State-store commits are not advertised as
production-grade distributed transactions or high availability.

## 11. Research Interfaces And Evaluation

- `/v1/calls/evaluate` returns `advisory_only=true` and mutates no state.
- `/v1/tools/{tool}/capability` exposes inferred facts and evidence.
- `/v1/sessions/{session}/state` exposes fact state only.
- `/v1/sessions/{session}/rule-state` exposes detection state only when research debug is enabled.
- `SecurityDecision` exposes matched event/object identifiers, state facts, relation evidence, and
  reasons for false-positive/false-negative analysis.

The executable test corpus covers single events, state labels, linked and benign provenance,
sequence constraints, cumulative reads, rewrite/recheck, approval, trusted authorization,
multi-agent task scope, local concurrency, API behavior, and MCP protocol mediation. Intended paper
ablations compare stateless ECA, state labels, temporal sequences, provenance constraints, and
aggregate windows.

## 12. Validity Limits

- Hidden tool side effects can exceed a declared or inferred capability.
- Tool descriptions and schemas can be vague or adversarial.
- Digest provenance is incomplete by design.
- Bounded TTL/history/path limits can truncate long attacks.
- Deterministic content patterns do not solve prompt injection.
- The prototype does not provide complete IAM, secrets management, policy hot reload, production
  HA, GUI action security, OS monitoring, or general agent observability.
