# AgentGate Artifact Guide

## 1. Artifact Scope

The artifact implements the system described in `docs/plan.md` as an executable research
prototype. It contains:

- a protocol-neutral security IR and shared runtime;
- three independently testable security modules;
- 26 controlled tools across five domains;
- a FastAPI sidecar and Function/MCP/framework adapters;
- built-in deterministic policy evaluation and an OPA/Rego backend;
- optional OpenAI-compatible semantic analysis with generic, SUB, and PACKY configuration;
- AgentGateBench, TS-Bench import, AgentDojo bridge, baselines, metrics, and tuning.

The controlled tools never access the host filesystem, production network, or real business
systems. They operate on `MockBackend`, whose state can be snapshotted before and after a case.
For a detailed Chinese description of the implemented runtime, data models, module algorithms,
interfaces, and current limitations, see [system-implementation.md](system-implementation.md).

## 2. Source Layout

```text
src/agentgate/
├── models.py                    # security IR
├── llm/                         # OpenAI-compatible JSON analysis
├── modules/
│   ├── integrity/               # profile, fingerprint, injection boundary, sanitization
│   ├── authorization/           # task/call safety, contract, effects, policy, rewrite
│   └── trajectory/              # labels, graph, budgets, temporal state
├── policy/                      # built-in and OPA backends
├── runtime/                     # orchestration, audit, API, adapters
├── tools/
│   ├── filesystem/
│   ├── database/
│   ├── network/
│   ├── messaging/
│   └── business/
└── evaluation/                  # cases, metrics, baselines, external adapters
```

Tool implementations are deliberately separate from the three security modules. Adding a new
tool domain does not require changing integrity, authorization, or trajectory logic.

## 3. Runtime Data Flow

```text
Tool registration
  -> semantic profile and dual fingerprint
  -> instruction/data boundary check
  -> accept, restrict, or block

Candidate tool call
  -> reject policy-unsafe tasks and injected call objectives
  -> infer Action/Resource/Scope/Effect
  -> compare with TaskContract
  -> inspect trajectory labels, graph, budgets, and approval state
  -> allow, deny, rewrite, confirm, approve, or sandbox

Tool result
  -> inspect and sanitize untrusted instructions
  -> assign and propagate sensitivity labels
  -> update execution graph and cumulative state
  -> append audit evidence
```

Rewritten calls are normalized and evaluated again before execution. An approval token becomes
invalid after the first successful use, including across sessions held by the same gateway.

## 4. LLM-Assisted Analysis

The LLM is an untrusted semantic extractor and judge, not the final policy decision maker. It
supports tool profiling, task-contract extraction, task policy classification, instruction/data
classification, task-effect alignment even when no Agent rationale is provided, and semantic
sensitivity labeling of tool results. Entitlements are applied after contract extraction so the
LLM cannot grant actions, resources, effects, or record counts beyond enterprise policy. Final
enforcement is still performed by deterministic checks or OPA.

The client resolves credentials in this order:

```text
AGENTGATE_LLM_BASE_URL + AGENTGATE_LLM_API_KEY
SUB_URL + SUB_LLM_API
PACKY_API_URL
PACKY_API_KEY_DEFAULT
LLM_MODEL_DEFAULT
```

Base URLs without `/v1` are normalized automatically.

Enable it explicitly:

```bash
export AGENTGATE_LLM_ENABLED=true
.venv/bin/agentgate doctor
```

The API client uses `POST /chat/completions`, requests a JSON object, treats tool content as
external data in the system prompt, reuses a persistent HTTP connection, and retries transient
failures with exponential backoff. It falls back to deterministic analysis after retry exhaustion
unless `AGENTGATE_LLM_FAIL_CLOSED=true`. Trusted built-in tool declarations skip the semantic
injection fallback during startup; external declarations and every tool result remain eligible
for semantic analysis. Offline evaluation can batch independent semantic authorization decisions
and bound request concurrency without changing the runtime detector.

The sidecar exposes `POST /v1/contracts/build` and `POST /v1/calls/execute-task`. The latter
accepts a natural-language task, derives a contract, applies entitlements, and runs the normal
authorization and trajectory pipeline without requiring the caller to construct `TaskContract`.

LLM credentials use `SecretStr` and are not serialized into audit records or benchmark results.
However, calls and tool results are currently audited without field-level redaction, so sensitive
business data can still enter the audit JSONL. Production deployment requires audit redaction,
access control, encryption, and retention policies. `.env` is ignored by Git.

## 5. Policy Backends

The default `builtin` backend keeps unit tests and benchmark regression self-contained. OPA is
the external policy engine for system experiments. AgentGate submits an input document to OPA's
official Data API endpoint:

```text
POST /v1/data/agentgate/authorization/decision
```

Start the pinned OPA container and select it:

```bash
docker compose up -d opa
export AGENTGATE_POLICY_BACKEND=opa
.venv/bin/agentgate doctor
```

The Rego policy is in `policies/agentgate.rego`. OPA integration follows the official REST API:
https://www.openpolicyagent.org/docs/rest-api

## 6. Controlled Tools

The default registry contains 26 tools:

- filesystem: read, write, delete, search, list;
- database: order query/update/export, customer query, credential query;
- network: fetch, download, webhook, cloud upload, URL resolution;
- messaging: email, message, attachment upload, share link, internal notification;
- business: order lookup/refund, account lookup/update, service restart, token issue.

List their inferred profiles with:

```bash
.venv/bin/agentgate list-tools
```

## 7. Evaluation Workflow

### Local executable benchmark

```bash
make evaluate
make baselines
make tune
```

AgentGateBench currently contains 31 cases and 40 decision points over train/dev/test splits.
It is a deterministic regression and ablation suite. A perfect score on it only proves that the
implementation matches the fixture's stated policies; it is not evidence of real-world
generalization.

### TS-Bench

The pinned ToolSafe source is `MurrayTom/ToolSafe` revision
`46358fa424a927a895c6c8322f99032c4eb5155e`. The upstream TS-Bench JSON records contain the
instruction, interaction history, candidate action, tool environment, and a step safety score.

```bash
make fetch-benchmarks
.venv/bin/agentgate evaluate-toolsafe \
  --source benchmarks/external/toolsafe/TS-Bench \
  --output artifacts/results/toolsafe-full.json
```

The report includes separate `agentdojo`, `agentharm`, and `asb` metrics because they evaluate
different decisions: indirect prompt injection, task-level policy safety, and open-vocabulary
attacker-tool selection respectively.

Enable the semantic ASB path with:

```bash
AGENTGATE_LLM_ENABLED=true \
AGENTGATE_LLM_BATCH_SIZE=20 \
AGENTGATE_LLM_CONCURRENCY=4 \
.venv/bin/agentgate evaluate-toolsafe \
  --source benchmarks/external/toolsafe/TS-Bench/asb-traj/test/OPI_attack_success.json \
  --output artifacts/results/toolsafe-asb-opi-llm.json
```

The adapter sends no benchmark label or score to the LLM. Reports include provider request,
retry, and failure counts plus both official step metrics and stop-on-deny reachable trajectory
metrics. A missing source path or a directory with no JSON records fails explicitly instead of
producing a zero-case report.

Official source: https://github.com/MurrayTom/ToolSafe

### AgentDojo

The pinned source is `ethz-spylab/agentdojo` revision
`089ed468cf3ed0322acc66b0211f26d9d90dbf60`. `AgentDojoGuard` exposes registration, pre-call,
and post-result hooks that can be called from an AgentDojo `ToolsExecutor` replacement without
changing task suites or environment state validators. The post-result hook propagates labels and
updates the dynamic execution graph, rather than acting only as a text sanitizer.

Official source: https://github.com/ethz-spylab/agentdojo

## 8. Metrics and Iteration

The runner reports exact decision accuracy, precision, recall, F1, attack success rate, benign
completion rate, false-positive rate, and mean decision latency. Per-category results separate
integrity, authorization, and trajectory behavior. ToolSafe reports also replay each interaction
with stop-on-deny semantics. This secondary view excludes recorded steps that cannot execute after
an earlier denial and is always reported alongside the upstream step-level view.

The tuning script searches integrity severity and trajectory budget settings on the dev split.
For paper experiments, select settings on train/dev only, freeze them, then report test and
external benchmark results. Never tune on AgentDojo attack targets or TS-Bench test labels.

Required baselines are:

1. no guard;
2. static action/identity policy;
3. AgentGate without each core module;
4. full AgentGate with deterministic analysis;
5. full AgentGate with LLM semantic extraction;
6. OPA versus built-in policy backend overhead.

## 9. Verification

```bash
make lint
make test
make evaluate
```

`pytest` covers the tool environment, integrity detection, semantic fingerprints, task-level
authorization, entitlement-constrained LLM contracts, rationale-free call alignment, semantic
sensitivity labeling, least-privilege rewriting, source-to-sink blocking, approval replay,
FastAPI sidecar, OpenAI-compatible request shape, AgentDojo post-call state, OPA request shape,
and benchmark comparison. OPA was also validated against a live pinned 1.18.2 container.

Measured results and limitations are recorded in `docs/evaluation.md`.
