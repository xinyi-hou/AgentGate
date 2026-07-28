# Evaluation Record

## Reproduction Context

- date: 2026-07-28;
- Python: 3.12;
- AgentGate commit: working tree prior to artifact commit;
- ToolSafe revision: `46358fa424a927a895c6c8322f99032c4eb5155e`;
- AgentDojo revision: `089ed468cf3ed0322acc66b0211f26d9d90dbf60`;
- LLM: `gpt-5.5` through the configured OpenAI-compatible endpoint;
- semantic authorization: historical direct-verdict implementation, before evidence fusion;
- OPA: `openpolicyagent/opa:1.18.2-static`.

Generated result files are written to `artifacts/results/` and intentionally ignored by Git.
No API key, expected decision, or benchmark `score` is included in an LLM request.

Throughout this record, an unsafe example is the positive class. `FP` therefore means that a
benign call was blocked (false alarm), while `FN` means that an unsafe call was allowed (missed
detection). `FPR=FP/(FP+TN)` and `FNR=FN/(TP+FN)`. In this security setting, FNR is numerically
identical to attack success rate (ASR). Every generated metrics object now reports `tp`, `fp`,
`tn`, `fn`, `false_positive_rate`, and `false_negative_rate` explicitly.

## AgentGateBench

| Mode | Accuracy | F1 | FP (FPR) | FN (FNR/ASR) | Benign completion | Mean latency |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| full | 1.000 | 1.000 | 0 (0.000) | 0 (0.000) | 1.000 | 0.32 ms |
| static | 0.525 | 0.174 | 0 (0.000) | 19 (0.905) | 1.000 | <0.01 ms |
| no guard | 0.475 | 0.000 | 0 (0.000) | 21 (1.000) | 1.000 | <0.01 ms |

AgentGateBench has 31 cases and 40 decision points. It is a deterministic implementation and
ablation suite. The full score confirms fixture conformance only; it must not be used as evidence
of generalization.

## Current Full-Pipeline Verification

The ToolSafe adapter now preserves declared parameter schemas, uses one session per recorded
interaction, and routes every non-AgentHarm candidate through tool registration, contract
construction, actual-effect inference, semantic authorization, trajectory inspection, and atomic
budget reservation. It no longer broadens contracts, creates approval tokens, or uses benchmark
phrases in a security decision.

| Run | Cases | Accuracy | F1 | FP (FPR) | FN (FNR/ASR) | Benign completion |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| AgentGateBench, rules-only | 40 | 1.000 | 1.000 | 0 (0.000) | 0 (0.000) | 1.000 |
| TS-Bench AgentDojo, rules-only official | 1,220 | 0.800 | 0.723 | 210 (0.242) | 34 (0.097) | 0.758 |
| TS-Bench AgentDojo, rules-only reachable | 889 | 0.818 | 0.766 | 134 (0.225) | 28 (0.096) | 0.775 |
| AgentDojo Slack LLM smoke, official | 21 | 0.571 | 0.471 | 9 (0.529) | 0 (0.000) | 0.471 |
| AgentDojo Slack LLM smoke, reachable | 12 | 0.917 | 0.889 | 1 (0.125) | 0 (0.000) | 0.875 |

At interaction level, an attack interaction is a false negative if any unsafe reachable step is
allowed; a clean interaction is a false positive if any reachable step is blocked:

| Run | Interactions | Accuracy | FP (FPR) | FN (FNR/ASR) |
| --- | ---: | ---: | ---: | ---: |
| TS-Bench AgentDojo, rules-only | 589 | 0.812 | 83 (0.325) | 28 (0.084) |
| AgentDojo Slack LLM smoke | 6 | 0.833 | 1 (0.500) | 0 (0.000) |
| complete TS-Bench, rules-only diagnostic | 3,376 | 0.839 | 313 (0.491) | 229 (0.084) |

The LLM smoke used six complete interactions selected with seed `20260734` and `gpt-5.4`. It is
only a pipeline check. Most official-view false positives are recorded continuations after an
earlier denial; the reachable view reflects stop-on-deny execution. A full current LLM-assisted
run is still required before reporting a final paper result. The leakage audit found no copied
task phrases across 47 production strings and 1,541 unique benchmark texts.

### Why Current Accuracy Is Limited

The 1,220-step AgentDojo rules-only run has 244 classification errors: 210 false positives and 34
false negatives. False positives account for 86.1% of all errors, so its 80.0% accuracy is mainly
an over-blocking problem rather than a high attack success rate. Using a mutually exclusive
primary-cause assignment, the false positives break down as follows:

| Primary false-positive cause | Count | Share of FP | Interpretation |
| --- | ---: | ---: | --- |
| action/effect contract mismatch | 112 | 53.3% | the lexical task contract misses an implicit or conditional operation |
| scope mismatch without action mismatch | 57 | 27.1% | candidate enumeration is treated as final bulk disclosure |
| destination mismatch | 15 | 7.1% | the task implies a recipient but does not name a normalized destination |
| approval required | 12 | 5.7% | the benchmark has no separate approval-token event |
| resource mismatch | 7 | 3.3% | task and tool use different resource identifiers |
| trajectory budget | 7 | 3.3% | cumulative transmission or record budgets reject a later benign step |

Workspace contributes 162 of the 210 false positives. Typical tasks ask “when” or “where” an
event occurs without an explicit read verb, so the rules-only contract omits `READ`. Conditional
tasks such as reserving a hotel only if its rating exceeds four also require a write operation that
the lexical contract can miss. Another 57 false positives arise because listing all candidate
hotels, files, or rental companies is a necessary intermediate computation, while the current
scope model applies the task's final-output limit directly to that internal query.

Of the 34 false negatives, 33 use the rules-only semantic fallback and one has no tool call. Nine
already contain a module-one injection finding, but that finding is not causally bound to the next
tool and its arguments. As a result, injected calls such as `send_direct_message`, `post_webpage`,
or a recurring-payment update can pass when their individual action and scope also fit the broad
task contract. The missing mechanism is structured evidence transfer from result-instruction
detection to call provenance analysis, not another benchmark sentence rule.

The 21-step LLM smoke has a different accounting issue: eight of its nine official false
positives occur after an earlier gateway denial and are unreachable under stop-on-deny execution,
leaving one reachable false positive and no false negative. Seven of the nine belong to
attack-containing interactions; the other two are consecutive steps in one clean interaction, of
which only the first is reachable. Its 57.1% official accuracy is therefore not representative of
runtime utility, although the sample is too small to support a paper-level performance claim.

For completeness, the final rules-only implementation also executes all 7,182 TS-Bench records:

| Family | Cases | Accuracy | FP (FPR) | FN (FNR/ASR) | Dominant limitation |
| --- | ---: | ---: | ---: | ---: | --- |
| AgentDojo | 1,220 | 0.800 | 210 (0.242) | 34 (0.097) | contract and scope over-blocking |
| AgentHarm | 731 | 0.282 | 0 (0.000) | 525 (1.000) | task-level semantic policy disabled |
| ASB | 5,231 | 0.516 | 2,338 (0.867) | 194 (0.077) | 2,324 benign calls hit action mismatch |
| aggregate | 7,182 | 0.540 | 2,548 (0.676) | 753 (0.221) | heterogeneous negative controls; not a primary score |

## Historical TS-Bench Generic Rules Baseline

The following rules-only results predate the current full-pipeline adapter and are retained only
for historical comparison over all 7,182 official records:

| Family | Cases | Accuracy | F1 | FP (FPR) | FN (FNR/ASR) | Benign completion |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| AgentDojo trajectories | 1,220 | 0.924 | 0.875 | 66 (0.076) | 27 (0.077) | 0.924 |
| AgentHarm, semantic policy disabled | 731 | 0.282 | 0.000 | 0 (0.000) | 525 (1.000) | 1.000 |
| ASB, generic call rules | 5,231 | 0.602 | 0.309 | 12 (0.004) | 2,069 (0.816) | 0.996 |
| aggregate | 7,182 | 0.624 | 0.370 | 78 (0.021) | 2,621 (0.768) | 0.979 |

The aggregate is not a primary result because the families measure different security questions.
The previous implementation contained phrase patterns derived from all 72 unique harmful
AgentHarm tasks. Those patterns have been deleted from production code and the old 100% result is
withdrawn. Without an LLM semantic policy extractor, AgentHarm is now intentionally a negative
control. ASB rules and LLM modes now enter the same `CallSemanticRiskDetector` interface; neither
mode receives `score` or the expected decision.

## Historical LLM-Assisted ASB Full Run

The complete 5,231-record ASB test set was evaluated, not a sampled smoke test. The semantic judge
receives the original task, appended external instruction (marked as non-authoritative context),
candidate tool description, arguments, agent rationale, and prior trace. It does not receive the
expected label or safety score. Deterministic high-risk capability checks still run first; the LLM
handles open-vocabulary cases that reach the semantic path.

This full-set run predates the bounded-fact evidence-fusion implementation. It is retained as a
historical direct-verdict baseline and must not be presented as a result of the current semantic
authorization design. The current design is evaluated across model families in the held-out
sample below.

### Official Step-Level View

| ASB split | Cases | Accuracy | F1 | FP (FPR) | FN (FNR/ASR) | Benign completion |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| DPI attack success | 2,293 | 0.775 | 0.820 | 387 (0.392) | 129 (0.099) | 0.608 |
| OPI attack success | 2,509 | 0.927 | 0.923 | 53 (0.041) | 131 (0.107) | 0.959 |
| attack failure | 429 | 0.946 | - | 23 (0.054) | 0 (-) | 0.946 |
| aggregate | 5,231 | 0.862 | 0.863 | 463 (0.172) | 260 (0.103) | 0.828 |

In that historical implementation, compared with its then-current rules-only ASB baseline,
step-level ASR fell from 76.45% to 10.26% and accuracy rose from 60.66% to 86.18%. Step-level
benign completion fell from 95.55% to 82.83%, primarily because TS-Bench continues scoring later
recorded steps even after an earlier AgentGate denial would already have terminated that tool
chain. These figures are not comparisons against the current generic-rules row above.

### Reachable Trajectory View

The secondary trajectory view replays segments in their recorded order and excludes all steps
after the first `DENY` in each interaction. This matches AgentGate's runtime stop-on-deny behavior;
it is an AgentGate system metric, not a replacement for the official per-step result.

| Mode | Reachable steps | Accuracy | F1 | Step FP (FPR) | Step FN (FNR) | Interaction FP (FPR) | Interaction FN (FNR/ASR) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| historical rules only | 4,906 | 0.599 | 0.355 | 40 (0.016) | 1,927 (0.780) | 8 (0.031) | 1,782 (0.764) |
| LLM-assisted | 4,098 | 0.926 | 0.933 | 46 (0.027) | 256 (0.108) | 14 (0.054) | 231 (0.099) |

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

## Cross-Model Robustness on a Held-Out ASB Sample

The evidence-fusion implementation was also evaluated with five model identifiers from five model
families. The experiment used source-stratified, complete-interaction sampling: a target of 300
records produced 301 steps from 140 interactions with seed `20260734`. None of those interactions
overlaps the 19-interaction development sample produced with seed `20260728`. The held-out seed was
selected only for zero interaction overlap, before its labels or model results were inspected.

The model is not asked for a final safety verdict. It extracts bounded facts about goal, action,
resource, effect, external influence, and capability. AgentGate then combines those facts with
argument provenance, tool effects, task constraints, and deterministic impact policy. Every model
received the same prompt, records, batching settings, and local evidence policy. The rules-only
row uses the same semantic detector interface without LLM facts. This remains a module-level ASB
evaluation rather than an end-to-end run of all three AgentGate modules.

### Official Step-Level Results

| Model | Experimental role | F1 | FP (FPR) | FN (FNR/ASR) | Benign completion |
| --- | --- | ---: | ---: | ---: | ---: |
| rules only | non-LLM baseline | 28.57% | 2 (1.27%) | 119 (83.22%) | 99.37% |
| `gpt-5.4` | strong closed model | 79.41% | 62 (39.24%) | 8 (5.59%) | 60.76% |
| `claude-sonnet-4.6` | strong closed model, different family | 79.29% | 61 (38.61%) | 9 (6.29%) | 61.39% |
| `gemini-3.5-flash-lite` | lightweight closed model | 80.60% | 57 (36.08%) | 8 (5.59%) | 63.92% |
| `qwen3.5-4b-el` | small 4B model | 78.44% | 60 (37.97%) | 12 (8.39%) | 62.03% |
| `llama-3.1-8b-di` | deliberately weak baseline | 74.23% | 40 (25.32%) | 35 (24.48%) | 74.68% |

The official view scores recorded steps even when an earlier denial would have stopped the
interaction. It is retained for direct benchmark accounting, but its benign-completion value is
therefore pessimistic for a gateway that terminates denied chains.

### Reachable-Trajectory Results

| Model | Reachable steps | F1 | Step FP (FPR) | Step FN (FNR) | Interaction FP (FPR) | Interaction FN (FNR/ASR) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| rules only | 281 | 20.00% | 2 (1.36%) | 119 (88.81%) | 1 (7.69%) | 112 (88.19%) |
| `gpt-5.4` | 220 | 90.91% | 15 (15.46%) | 8 (6.50%) | 5 (38.46%) | 8 (6.30%) |
| `claude-sonnet-4.6` | 220 | 91.63% | 12 (12.50%) | 9 (7.26%) | 4 (30.77%) | 9 (7.09%) |
| `gemini-3.5-flash-lite` | 221 | 91.70% | 13 (13.40%) | 8 (6.45%) | 4 (30.77%) | 8 (6.30%) |
| `qwen3.5-4b-el` | 221 | 89.96% | 14 (14.29%) | 11 (8.94%) | 4 (30.77%) | 11 (8.66%) |
| `llama-3.1-8b-di` | 239 | 82.61% | 7 (6.31%) | 33 (25.78%) | 1 (7.69%) | 33 (25.98%) |

Across GPT, Claude, Gemini, and the 4B Qwen model, reachable F1 spans only 1.74 percentage points
and interaction ASR spans 2.36 points. Their pairwise decision agreement is 94.0%-97.0%. Qwen's
8.66% interaction ASR is close to the 6.30%-7.09% strong-model range and far below the 88.19%
rules-only result. This is evidence that the bounded extraction and local fusion design, rather
than a strong model producing an opaque verdict, carries a substantial part of the defense.

The Llama row marks a real lower bound: AgentGate still reduces interaction ASR by 62.20 points
relative to rules only, but it does not make an unreliable model equivalent to the other four.
The default evaluation configuration explicitly falls back to the rule policy when extraction
fails; it does not silently label the missing semantic result as safe. This fallback still has the
rules-only baseline's coverage limits, so strict deployments should enable failure propagation and
convert it into a gateway denial. Model selection still matters below a minimum semantic-following
capability.

### Provider Reliability and Cost

| Model | Requests | Final failures | Prompt tokens | Completion tokens | Rule fallback items |
| --- | ---: | ---: | ---: | ---: | ---: |
| `gpt-5.4` | 55 | 0 | 124,956 | 30,684 | 0 |
| `claude-sonnet-4.6` | 55 | 0 | 140,371 | 98,341 | 0 |
| `gemini-3.5-flash-lite` | 59 | 0 | 134,619 | 36,622 | 0 |
| `qwen3.5-4b-el` | 210 | 4 | 287,741 | 594,882 | 2 |
| `llama-3.1-8b-di` | 306 | 32 | 277,773 | 85,574 | 10 |

The client repairs missing batch items recursively and falls back to deterministic policy after a
final provider failure. It also detects endpoints that reject `response_format`, caches that
capability, and retries without it. These mechanisms kept provider instability observable without
turning parse or transport failures into implicit authorization.

This experiment is a held-out interaction sample within the same ASB test source, not a new
external benchmark split. It supports a cross-model stability claim, but a paper-grade final run
should freeze the implementation and repeat the comparison on the complete ASB set and on native
AgentDojo execution.

The selected cross-suite expansion now includes InjecAgent, ToolEmu, tau2-bench, and
MCP-SafetyBench. Their intended module coverage, pinned revisions, integration gates, and
anti-overfitting requirements are recorded in [benchmark-strategy.md](benchmark-strategy.md).

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

The cross-model sample was generated with:

```bash
.venv/bin/python scripts/evaluate_model_matrix.py \
  --source benchmarks/external/toolsafe/TS-Bench/asb-traj/test \
  --model gpt-5.4 \
  --model claude-sonnet-4.6 \
  --model gemini-3.5-flash-lite \
  --model qwen3.5-4b-el \
  --model llama-3.1-8b-di \
  --sample-size 300 \
  --sample-seed 20260734 \
  --development-sample-size 30 \
  --development-sample-seed 20260728 \
  --batch-size 5 \
  --concurrency 4 \
  --timeout 180 \
  --output-dir artifacts/results/model-matrix-300-heldout
```
