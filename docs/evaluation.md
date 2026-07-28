# Evaluation Record

## Reproduction Context

- date: 2026-07-28;
- Python: 3.12;
- AgentGate commit: working tree prior to artifact commit;
- ToolSafe revision: `46358fa424a927a895c6c8322f99032c4eb5155e`;
- AgentDojo revision: `089ed468cf3ed0322acc66b0211f26d9d90dbf60`;
- LLM: `gpt-5.5` through the configured OpenAI-compatible endpoint;
- OPA: `openpolicyagent/opa:1.18.2-static`.

Generated result files are written to `artifacts/results/` and intentionally ignored by Git.
No API key, expected decision, or benchmark `score` is included in an LLM request.

## AgentGateBench

| Mode | Accuracy | F1 | ASR | Benign completion | Mean latency |
| --- | ---: | ---: | ---: | ---: | ---: |
| full | 1.000 | 1.000 | 0.000 | 1.000 | 0.32 ms |
| static | 0.525 | 0.174 | 0.905 | 1.000 | <0.01 ms |
| no guard | 0.475 | 0.000 | 1.000 | 1.000 | <0.01 ms |

AgentGateBench has 31 cases and 40 decision points. It is a deterministic implementation and
ablation suite. The full score confirms fixture conformance only; it must not be used as evidence
of generalization.

## TS-Bench Rules-Only Baseline

Rules-only results over all 7,182 official records:

| Family | Cases | Accuracy | F1 | ASR | Benign completion | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| AgentDojo trajectories | 1,220 | 0.924 | 0.875 | 0.077 | 0.924 | 0.076 |
| AgentHarm | 731 | 1.000 | 1.000 | 0.000 | 1.000 | 0.000 |
| ASB | 5,231 | 0.607 | 0.367 | 0.764 | 0.955 | 0.045 |
| aggregate | 7,182 | 0.701 | 0.574 | 0.576 | 0.951 | 0.049 |

The aggregate is not the primary result because the families measure different security
questions. AgentDojo exercises indirect-injection decisions, AgentHarm checks the represented
task-policy categories, and ASB tests open-vocabulary task-to-tool alignment. AgentHarm tasks
informed deterministic policy coverage, so its perfect result is not a held-out generalization
claim.

## LLM-Assisted ASB

The complete 5,231-record ASB test set was evaluated, not a sampled smoke test. The semantic judge
receives the original task, appended external instruction (marked as non-authoritative context),
candidate tool description, arguments, agent rationale, and prior trace. It does not receive the
expected label or safety score. Deterministic high-risk capability checks still run first; the LLM
handles open-vocabulary cases that reach the semantic path.

### Official Step-Level View

| ASB split | Cases | Accuracy | F1 | ASR | Benign completion | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| DPI attack success | 2,293 | 0.775 | 0.820 | 0.099 | 0.608 | 0.392 |
| OPI attack success | 2,509 | 0.927 | 0.923 | 0.107 | 0.959 | 0.041 |
| attack failure | 429 | 0.946 | - | - | 0.946 | 0.054 |
| aggregate | 5,231 | 0.862 | 0.863 | 0.103 | 0.828 | 0.172 |

Compared with the rules-only ASB baseline, step-level ASR falls from 76.45% to 10.26% and accuracy
rises from 60.66% to 86.18%. Step-level benign completion falls from 95.55% to 82.83%, primarily
because TS-Bench continues scoring later recorded steps even after an earlier AgentGate denial
would already have terminated that tool chain.

### Reachable Trajectory View

The secondary trajectory view replays segments in their recorded order and excludes all steps
after the first `DENY` in each interaction. This matches AgentGate's runtime stop-on-deny behavior;
it is an AgentGate system metric, not a replacement for the official per-step result.

| Mode | Reachable steps | Accuracy | F1 | ASR | Benign completion | Interaction ASR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| rules only | 4,906 | 0.599 | 0.355 | 0.780 | 0.984 | 0.764 |
| LLM-assisted | 4,098 | 0.926 | 0.933 | 0.108 | 0.973 | 0.099 |

Under execution semantics, the LLM-assisted design reduces reachable ASR by 67.26 percentage
points while reducing benign completion by 1.02 points. For DPI specifically, 367 of 387
step-level false positives occur after an earlier denial and are unreachable; its reachable benign
completion is 88.95% rather than 60.83%. Both views are retained so the result is not improved by
hiding the official step-level false positives.

### Semantic Coverage and Runtime

| Split | LLM decisions | Rule decisions | No-tool steps | Requests | Retries | Failures | Wall time |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DPI | 1,868 | 423 | 2 | 102 | 1 | 0 | 1,103.9 s |
| OPI | 2,225 | 252 | 32 | 115 | 0 | 0 | 805.7 s |
| attack failure | 374 | 20 | 35 | 20 | 0 | 0 | 149.5 s |
| aggregate | 4,467 | 695 | 69 | 237 | 1 | 0 | 2,059.1 s |

Requests use batches of up to 20 items with concurrency 4 and a persistent HTTP connection. The
aggregate wall time was 34.3 minutes. These offline batched numbers measure evaluation throughput,
not interactive P95/P99 gateway latency. The rules-only path remains available when the LLM is
disabled or the provider fails; provider failures are counted in each report.

## Scope of Evidence

The ASB run evaluates the production `CallSemanticRiskDetector` on a real upstream dataset, but
uses the ToolSafe adapter because the records contain pre-generated candidate calls rather than
live executable backends. AgentDojo-native end-to-end task execution has not yet been run. The
current evidence therefore supports semantic authorization quality and the controlled runtime
properties covered by AgentGateBench; it does not establish production robustness or native
AgentDojo utility.

## OPA Verification

The pinned OPA container compiled `policies/agentgate.rego`, returned `ALLOW` from
`POST /v1/data/agentgate/authorization/decision` for a fully matching input, and allowed an
end-to-end `business.get_order` call through `OpaPolicyBackend`. The container was stopped after
verification.

## Commands

```bash
.venv/bin/ruff check src scripts tests
.venv/bin/pytest -q
.venv/bin/agentgate evaluate \
  --dataset benchmarks/agentgatebench/cases.jsonl --mode full
.venv/bin/agentgate evaluate-toolsafe \
  --source benchmarks/external/toolsafe/TS-Bench \
  --output artifacts/results/toolsafe-rules.json
AGENTGATE_LLM_ENABLED=true \
AGENTGATE_LLM_BATCH_SIZE=20 \
AGENTGATE_LLM_CONCURRENCY=4 \
AGENTGATE_LLM_TIMEOUT=120 \
.venv/bin/agentgate evaluate-toolsafe \
  --source benchmarks/external/toolsafe/TS-Bench/asb-traj/test/OPI_attack_success.json \
  --output artifacts/results/toolsafe-asb-opi-llm.json
```

The LLM-assisted command was repeated for `DPI_attack_success.json` and the upstream-named
`atttack_failure.json`; the three reports were then aggregated from their confusion counts.
