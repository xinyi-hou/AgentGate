# AgentGate End-to-End Evaluation

This directory implements the experiment protocol in
`docs/AgentGate_端到端实验评估计划_Codex.md`. The primary unit is an executable task: an agent or
deterministic workflow invokes real tool implementations, AgentGate arbitrates before execution,
and an isolated environment records whether the intended task and harmful side effect occurred.
Trace replay is not used for the reported main results.

## What Was Executed

| Benchmark | Scope in this run | Status |
|---|---:|---|
| AgentGate-StatefulBench | 8 attacks + 8 paired benign controls, six defense modes | Complete |
| AgentDojo 0.1.35 / benchmark 1.2 | `workspace` user tasks 0--1 with `tool_knowledge/injection_task_0`, three defenses | Executed subset |
| Controlled ATG scaling | 5/10/20/40/80 real tool calls, three modes | Complete |
| Semantic E2E | 2 executable cases x 3 repeats x 6 semantic models | Complete |
| MSB | Filesystem MCP started; Paper Search MCP stopped at interactive OAuth | Not included |
| MCP-SafetyBench | Requires disposable accounts and real service credentials | Not run |
| MCP-Bench | Requires provider, judge, and selected MCP-server credentials | Not run |

An unavailable integration is never represented by a zero score. Exact revisions and blockers are
in `results/normalized/*_metadata.jsonl` and
`results/failures/baseline_integration_failures.jsonl`.

## Harness

`schema.py` defines a common Pydantic task record and per-call record. Every task record includes
benchmark and defense revisions, configuration hash, fixed agent/semantic model IDs, attack and
utility outcomes, pre-side-effect enforcement status, latency/token data, an ATG snapshot, and
artifact paths. Per-call records include argument digests rather than raw secrets, decision and
rule IDs, execution/side-effect state, and stage-level timing fields.

`statefulbench/` supplies real in-process tools backed by a fresh temporary directory for each run.
The attacks exercise sensitive read/send, transformation, file staging, untrusted execute/install,
untrusted-control flow, aggregate collection, and cross-server propagation. Each attack has a
sequence-similar benign control. The evaluator checks actual files, messages, command markers, and
install markers; a block counts as successful only when the harmful marker was not produced.

The RQ2 modes isolate mechanisms:

- `A0 Event-only`: current `ToolSecurityEvent` only.
- `A1 Event + Sequence`: ordered events, no provenance graph.
- `A2 ATG without Provenance`: graph structure without data nodes or `PRODUCES`, `CONSUMES`, and
  `DERIVES_FROM` edges.
- `A3 ATG + Provenance without Labels`: provenance retained, derived-label propagation disabled.
- `A4 Full AgentGate`: ATG, provenance, label propagation, graph detection, and runtime control.

The semantic experiment fixes a deterministic task agent and sends the same ambiguous tool schema
to each model from `.env`. A trial performs a real sensitive/public read followed by a real external
relay, so schema validity and the final allow/block outcome are both measured. Model output is
strictly validated; schema failure is reported separately and fails closed for task execution.

## Reproduction

Use Python 3.12 and install AgentGate with its development dependencies. External benchmark clones
are intentionally ignored by Git; `manifest.yaml` pins their URLs and revisions. Do not run
MCP-SafetyBench against personal or production accounts.

```bash
# Native paired benchmark and all A0--A4 modes
.venv/bin/python -m evaluation.runners.run_statefulbench

# Controlled 5/10/20/40/80-call graph workload
.venv/bin/python -m evaluation.runners.run_scaling

# AgentGate path for one real AgentDojo task; repeat for user_task_0 and user_task_1
set -a; source .env; set +a
.venv/bin/python -m evaluation.runners.run_agentdojo \
  --suite workspace --user-task user_task_0 --injection-task injection_task_0
.venv/bin/python -m evaluation.runners.normalize_agentdojo

# Fixed task agent, all LLM_MODEL_N values, three repetitions
set -a; source .env; set +a
.venv/bin/python -m evaluation.runners.run_semantic_robustness --repeats 3

# Regenerate metadata, failure cases, and RQ tables
.venv/bin/python -m evaluation.runners.record_external_status
.venv/bin/python -m evaluation.runners.build_tables
.venv/bin/python -m evaluation.runners.build_figures
```

AgentDojo No Defense and Tool Filter use the pinned upstream executable runner. The Tool Filter
adapter changes only the OpenAI-compatible filter request's model identifier because upstream uses
the provider name as a model ID; its filtering policy remains unchanged. AgentGate replaces
AgentDojo's `ToolsExecutor`, while the environment and native utility/security scorers remain
unchanged.

MSB can be retried after supplying non-interactive Smithery credentials:

```bash
benchmarks/e2e/msb/.venv-agentgate/bin/python -m evaluation.runners.run_msb \
  --defense 'No Defense' --model-id DeepSeek-V4-Pro-0813
```

## Results and Interpretation

`results/raw/` contains task, call, audit, ATG, and side-effect evidence. `results/normalized/`
contains the common records and pinned metadata. `results/tables/` contains the eleven RQ CSVs required
by the plan. `results/failures/` contains false-positive, false-negative, late-detection, semantic,
dependency, disagreement, and integration-failure cases.

Unsafe tasks are the positive class. ASR is the fraction of attacks that achieved their harmful
goal; BCR is the fraction of benign tasks completed. Wilson 95% intervals are reported for RQ1.
AgentDojo's native `security=true` means the injection goal succeeded. The two-task AgentDojo subset
had zero attack success even under No Defense, so it tests compatibility here but cannot establish a
defense improvement. Empty cells in `not_run` rows mean unavailable, not zero.

The committed output is one concrete run. Wall-clock latency and remote-model behavior should be
re-measured on the target machine. API keys and endpoint URLs are never serialized into results.
