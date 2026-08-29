# AgentGate Research Architecture

## 1. Research Position

AgentGate studies runtime security at the structured tool-execution boundary. It normalizes
heterogeneous calls, incrementally reconstructs an Agent Transition Graph (ATG), and checks a
noncommitted request extension before allowing the tool to produce effects. It does not require
prompts, chain-of-thought, token traces, or whole-program instrumentation.

```text
CanonicalToolCall -> ToolSecurityEvent(REQUEST) -> Candidate ATG
  -> graph reasoning -> enforcement -> ToolSecurityEvent(RESULT)
  -> committed ATG delta
```

The complete-mediation claim covers only calls routed through the gateway. Direct syscalls,
subprocesses, sockets, filesystem APIs, or SDK calls remain outside the model.

## 2. Adapted Security Mechanisms

| Source mechanism | AgentGate adaptation | Deliberate omission |
| --- | --- | --- |
| Reference Monitor | pre-execution mediation of every routed tool call | no kernel mediation |
| Falco/Tetragon ECA | predicates over normalized request events | no kernel event taxonomy |
| EQL/CEP | typed temporal paths and `NEXT` edges | no general query language |
| IFC/taint/DLP | typed DataObjects and security labels | no byte/instruction taint |
| Provenance IDS | `PRODUCES/CONSUMES/DERIVES_FROM` paths | no whole-system provenance |
| SIEM correlation | indexed event-time windows and projected thresholds | no SIEM platform |
| MalSkills | operation/operand/value-flow separation and symbolic-first LLM assistance | no static skill SDG |

## 3. Three Modules

### Module 1: Tool-call security semantic abstraction

Input: framework/MCP/sidecar request, tool declaration, and trusted runtime identity. Output:
`CanonicalToolCall`, then REQUEST/RESULT `ToolSecurityEvent` values.

All adapters produce the same canonical identity, scope, arguments, timestamp, and source metadata.
An explicit capability is preferred; deterministic rules infer common operations and argument
bindings; an optional schema-constrained LLM resolver handles ambiguity. The LLM extracts facts
only and cannot return an enforcement action.

### Module 2: Runtime Agent Transition Graph construction

Input: prior committed graph plus REQUEST or actual RESULT. Output: a noncommitted
`CandidateGraphExtension` or committed `GraphDelta`.

The ATG is a directed typed property graph with five node types:

```text
Agent, ToolEvent, Resource, DataObject, TrustDomain
```

and nine edge types:

```text
NEXT, PERFORMS, OPERATES_ON, PRODUCES, CONSUMES,
DERIVES_FROM, TARGETS, DELEGATES_TO, PARENT_OF
```

Single-agent, multi-tool, and multi-agent executions use this same graph schema. Task and agent
scope are attributes, not different graph implementations.

### Module 3: Graph-based stateful detection and enforcement

Input: committed ATG, candidate extension, policy, and optional trusted task authorization. Output:
one monotonic `SecurityDecision` with rule, node, edge, object, and label evidence.

Symbolic graph and aggregate rules run first. Optional LLM graph analysis receives only a bounded
local subgraph and produces relation evidence; it cannot directly block. Enforcement supports
ALLOW, AUDIT, shrink-only RESTRICT, bound one-time approval, and BLOCK.

## 4. Unified Semantic Model

`CanonicalToolCall` carries call/tool identity, principal/agent/session/task/parent scope, arguments,
time, source framework/transport/metadata, approval token, and context hints. It deliberately has no
risk or policy fields.

`ToolCapability` describes possible operation, resource, argument bindings, input/output data
types, effects, and output trust. The operation taxonomy is:

```text
READ WRITE SEND EXECUTE DELETE AUTH PRIVILEGE INSTALL
```

`ToolSecurityEvent` instantiates the capability with actual arguments and context. It separates:

- operation from resource and operand;
- input objects from output objects;
- destination from its trust domain;
- proposed REQUEST effects from observed RESULT facts;
- deterministic/LLM evidence from policy decisions.

## 5. Graph Construction Semantics

The physical graph is partitioned by `(principal_id, session_id)`. Nodes and edges retain task and
agent scope. High-confidence cross-agent data flow is allowed inside one task; different tasks do
not automatically share DataObjects for matching.

A REQUEST builds a candidate Agent, ToolEvent, Resource/Data/TrustDomain relation set for detection.
It is never written to `GraphStore`. BLOCK and approval-pending therefore create no historical fact.

A successful RESULT rebuilds and commits the delta. READ/WRITE may produce DataObjects. A WRITE
that consumed a parent creates `DERIVES_FROM`, and labels propagate from parent to child. A failed
RESULT may commit a FAILED ToolEvent plus performance/temporal/delegation audit edges, but no
resource, target, data, or effect relations.

`NEXT` captures order only. Data causality requires `CONSUMES` and `DERIVES_FROM`; `PARENT_OF` and
`DELEGATES_TO` capture orchestration/control structure without claiming data flow.

## 6. Labels And Provenance

Data labels include sensitive categories, trust/origin, and artifact/execution properties:

```text
SENSITIVE, CREDENTIAL, SECRET, PERSONAL, FINANCIAL, INTERNAL_DATA
TRUSTED, UNTRUSTED, INTERNAL_ORIGIN, EXTERNAL_ORIGIN
USER_PROVIDED, TOOL_PROVIDED, SUSPICIOUS_CONTROL_CONTENT
EXECUTABLE, PERSISTENT_ARTIFACT, CONFIGURATION, PRIVILEGED_CONTEXT
```

Deterministic dependency recovery uses structured object references, normalized values, containment,
file paths, hashes, and simple URL/Base64 normalization. It intentionally does not claim complete
dynamic taint. An optional dependency resolver sees a bounded same-task candidate set and can add a
relation only when the referenced object exists and confidence exceeds the configured threshold.

## 7. Detection Semantics

Current graph patterns cover:

- sensitive or derived data consumed by an unknown-external SEND;
- credential data consumed by AUTH;
- untrusted data consumed by EXECUTE or INSTALL;
- external data persisted and then executed;
- cross-agent variants through shared DataObjects;
- projected sensitive-read volume across an event-time window.

A temporal untrusted-read context without a proven dependency is weaker evidence and requests
approval rather than producing a high-confidence provenance BLOCK. This distinguishes sequence
correlation from causal data flow.

Decision ordering is monotonic:

```text
ALLOW < AUDIT < RESTRICT < REQUIRE_APPROVAL < BLOCK
```

`SecurityDecision` records matched node/edge/event/object identifiers, propagated labels, relation
evidence, reasons, rewrite arguments, and approval identifiers. The research evidence endpoint
returns the selected local path without DataObject fingerprints.

## 8. Runtime Invariants

1. Unknown or executor-less tools fail before execution.
2. Detection always runs before a mediated executor.
3. Advisory evaluation never mutates the graph.
4. BLOCK and pending approval do not enter the committed graph.
5. Failed calls do not create successful-effect relations.
6. RESTRICT is shrink-only and triggers complete re-normalization and re-detection.
7. Approval binds principal, session, call, tool, and effective argument digest.
8. Caller input cannot clear labels or upload its own trusted authorization.
9. Runtime time replaces caller waiting time at the mediation boundary.
10. A session coordinator covers evaluation, execution, and graph commit.

## 9. Storage And Incrementality

`GraphIndex` maintains events by operation/task, data by label/task/fingerprint, latest events by
agent/task/context, call-to-event lookup, and incoming/outgoing adjacency. Online rule evaluation
uses those indexes and bounded provenance traversal instead of rescanning the complete graph.

Memory mode provides one-process locking and TTL. Redis mode stores the graph with optimistic
WATCH/MULTI updates and uses a Redis session lock across evaluation, tool execution, and commit. It
supports multi-instance research experiments but does not claim production distributed transaction
or availability guarantees.

Legacy `SessionSecurityState` and `RuleMatchState` are updated as compatibility mirrors for existing
benchmarks and APIs. They are not the authoritative inputs of the new graph risk path.

## 10. LLM Budget And Trust Boundary

LLM calls are optional and selective:

```text
normal call               -> deterministic only
ambiguous tool semantics  -> SemanticResolver
ambiguous value relation  -> DependencyResolver
ambiguous local graph     -> optional GraphRiskResolver evidence
```

All shipped resolver adapters validate strict Pydantic schemas. Semantic and dependency resolvers
cannot produce control actions. Graph risk output can only add AUDIT evidence in the current
runtime; deterministic policy still controls blocking. Telemetry records call reason and latency.

External resolvers can receive tool declarations or tool arguments. They are disabled by default,
and experiments must explicitly select a provider within an acceptable data boundary.

## 11. Deployment And Evaluation Interfaces

In-process adapters support function tools, LangGraph callback order, and OpenAI Agents-style
callbacks. The MCP proxy mediates real `tools/call` requests over STDIO or Streamable HTTP, making it
usable by Codex and other MCP clients without modifying agent source. The HTTP sidecar covers custom
frameworks with structured calls.

Research endpoints include:

```text
GET /v1/tools/{tool}/semantic-profile
GET /v1/sessions/{session}/graph
GET /v1/decisions/{decision}/evidence
```

Capability extraction and provenance extraction can be evaluated separately from end-to-end
detection. Runtime outcomes expose LLM invocation telemetry, while graph evidence supports
false-positive and false-negative analysis.

## 12. Validity Limits

- Unmediated behavior is invisible.
- Encrypted, chunked, image-based, or complex semantic transformations can evade fingerprints.
- LLM-derived relations are probabilistic and must not be treated as ground truth.
- Tool schemas may omit critical business semantics.
- Task boundaries depend on trusted adapters supplying stable identity.
- The prototype stores a session graph, not a whole-host provenance graph.
- Compatibility state code remains in the repository and should not be mistaken for the ATG core.
