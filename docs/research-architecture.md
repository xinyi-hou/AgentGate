# AgentGate Research Architecture

## 1. Research Position

AgentGate studies stateful runtime security for structured agent tool calls. The research question is
whether session facts, data dependencies, and ordered call patterns can detect multi-step agent
attacks that a stateless per-call guard misses, without requiring full prompt or reasoning traces.

The system does not reproduce an operating-system runtime monitor. It narrows established security
ideas to the tool-call boundary and uses one pipeline:

```text
ToolSecurityEvent
    -> SessionSecurityState
    -> Stateful Detection
    -> Enforcement
```

## 2. Adapted Security Mechanisms

| Source mechanism | AgentGate adaptation | Deliberate omission |
| --- | --- | --- |
| Reference Monitor | One runtime gateway mediates every supported Adapter execution | No syscall or kernel mediation |
| Falco/Tetragon ECA | Declarative predicates over one normalized REQUEST event | No kernel event vocabulary |
| flowbits | Durable session labels set only by executed RESULT events | No packet-flow model |
| EQL/CEP | Ordered call sequences with task, resource, object, destination, data, and time constraints | No general-purpose query language |
| IFC/taint/DLP | Typed data objects and digest matching across arguments and results | No byte-level dynamic taint |
| Provenance IDS | Parent links record derived tool outputs and resource transitions | No whole-system provenance graph |
| SIEM correlation | Event-time windows with event or affected-record counts and thresholds | No general log analytics platform |

These mechanisms share a structured event representation, so the implementation can compare
stateless, state-label, aggregate, sequence-only, and provenance-aware variants without changing the
tool interface.

## 3. Runtime Invariants

The Reference Monitor is [AgentGateRuntime](../src/agentgate/runtime/gateway.py). Supported Adapters
register executors but invoke them only through `AgentGateRuntime.execute`.

The runtime enforces these invariants:

1. Unknown or executor-less tools fail closed.
2. Detection runs before the executor.
3. BLOCK and ISOLATE never create executed fact state.
4. RESTRICT may only reduce arguments and is evaluated again after rewriting.
5. Approval is bound to principal, session, call, tool, and argument digest and is consumed once.
6. State mutation accepts RESULT events only.
7. Event extraction and state maintenance never return security decisions.
8. Detection reads state but never mutates it.

## 4. Unified Event Model

`ToolSecurityEvent` represents identity, operation, resource, data, destination, trust domain, and
side effects. The operation vocabulary is deliberately small:

```text
READ WRITE SEND EXECUTE DELETE AUTH INSTALL
```

REQUEST events describe proposed behavior. RESULT events add success, result classification, and
affected count. This distinction prevents blocked calls from being treated as completed behavior.

Tool capability metadata is the primary normalization source. The deterministic inferer consumes
the tool name, description, input/output schema, and protocol annotations and records confidence,
evidence, and structural/semantic hashes. Ambiguous tools still require an explicit capability.
Protocol annotations remain untrusted hints. Optional semantic extractors may add structured facts;
they cannot directly make enforcement decisions.

Untrusted tool descriptions are scanned at registration. High-confidence control instructions in
untrusted results are replaced before the result reaches agent context or fact state. A task may
also carry a compiled `TaskContract`; the runtime checks principal, task, operation, resource,
scope, effects, and destination, and only performs shrink-only scope rewrites.

## 5. Session State

`SessionSecurityState` is a compact fact store with four views:

- `labels`: flowbit-style facts such as `HAS_CREDENTIAL` and
  `EXPOSED_TO_UNTRUSTED_CONTENT`;
- `counters`: session totals used for inspection and analysis;
- `sensitive_objects`: typed data objects with digest fingerprints and parent object identifiers;
- `recent_sensitive_events`: bounded input for CEP and window correlation.

The state is partitioned by `(principal, session_id)`. Memory and Redis implementations share the
same atomic update interface. History retention is automatically at least as long as the largest
configured aggregate or finite sequence window.

## 6. Stateful Detection

Detection merges four rule families with monotonic action precedence:

```text
ALLOW < AUDIT < RESTRICT < REQUIRE_APPROVAL < BLOCK < ISOLATE
```

### 6.1 Event-Condition-Action

`event_rules` evaluate one REQUEST event. Predicates can constrain operation, data type, trust
domain, resource type, effect, and context trust. Destructive command patterns, protected delete
targets, resource access, and scope reduction remain specialized single-event predicates because
they require argument-aware matching or rewriting.

### 6.2 State Labels

`state_rules` combine durable labels with a current-event predicate. For example, an external read
sets `EXPOSED_TO_UNTRUSTED_CONTENT`; a later EXECUTE matches a high-risk state rule. A trusted
current context can explicitly suppress this particular correlation.

### 6.3 Window Aggregation

`aggregate_rules` apply a condition to executed history within `[current_time - window, current_time]`.
The metric is either event count or affected-record count. The proposed REQUEST contributes its
requested scope, so a threshold is enforced before the tool executes.

### 6.4 Ordered Sequences

Each `sequence_rule` is compiled into a lightweight automaton and replayed over bounded sensitive
history plus the current event. A match must end at the current call. Constraints can require the
same task, resource, object, destination, data lineage, or maximum interval.

## 7. Data Flow And Provenance

A successful READ creates field-level typed `SensitiveObject` instances when field evidence is
available. Argument binding computes the same one-way signatures over later arguments; exact,
embedded, URL-decoded, Base64-decoded, token, or supplied digest matches attach object identifiers
to that event. A WRITE creates child objects whose `parent_object_ids` preserve the dependency:

```text
external READ -> D1 -> file WRITE -> D2 -> EXECUTE(D2)
```

`same_data` compares transitive object lineage rather than relying only on temporal proximity. This
is the main mechanism for separating a real exfiltration path from an unrelated later SEND.

Sensitive plaintext is not retained in state. The implementation does not claim semantic or
byte-level taint completeness.

## 8. Enforcement And Observation

The output is one `SecurityDecision`: ALLOW, AUDIT, RESTRICT, REQUIRE_APPROVAL, BLOCK, or ISOLATE.
Audit records cover requests, decisions, rule matches, results, state updates, approvals, and
isolation. Audit is supporting evidence for experiments, not the core detection abstraction.

AgentGate deliberately does not collect prompts, chain-of-thought, full model traces, syscalls,
browser pixels, or OpenTelemetry traces. This isolates the value of tool-boundary stateful detection.

## 9. Evaluation Model

The unit and integration suite is the executable mechanism corpus. It includes benign calls,
single-call violations, linked and unlinked exfiltration, credential use, download-write-execute,
untrusted-context escalation, windowed cumulative reads, rewrite safety, approval replay, isolation,
Adapters, API behavior, and audit redaction.

The intended paper ablations are:

1. stateless ECA only;
2. ECA plus flowbit-style labels;
3. ECA plus temporal sequences without data constraints;
4. full sequence plus provenance constraints;
5. full model plus aggregate windows.

Primary measurements are attack recall, benign false-positive rate, decision latency, and state
growth. The reproducible external evaluation uses pinned InjecAgent and TS-Bench revisions plus a
small protocol-native provenance replay. Fetch logic and aggregate paper results are tracked; raw
third-party datasets and generated reports remain ignored.

## 10. Validity Limits

- The monitor is complete only for tools routed through a supported Adapter.
- Capability declarations can under-approximate hidden executor side effects.
- Digest matching misses semantic rewrites, encryption, chunking, and many derived values.
- Bounded history and history count limits can truncate long sequences.
- Deterministic content patterns miss many implicit natural-language control instructions.
- Lexical task contracts over-block dynamic destinations and implicit intermediate operations.
- The prototype does not provide production identity, control-plane authorization, or distributed
  execution locking.

These limits define the research scope rather than hidden production claims.
