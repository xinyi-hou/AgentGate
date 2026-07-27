# Evaluation Record

## Reproduction Context

- date: 2026-07-27;
- Python: 3.12;
- AgentGate commit: working tree prior to artifact commit;
- ToolSafe revision: `46358fa424a927a895c6c8322f99032c4eb5155e`;
- AgentDojo revision: `089ed468cf3ed0322acc66b0211f26d9d90dbf60`;
- OPA: `openpolicyagent/opa:1.18.2-static`.

Generated result files are written to `artifacts/results/` and intentionally ignored by Git.

## AgentGateBench

| Mode | Accuracy | F1 | ASR | Benign completion | Mean latency |
| --- | ---: | ---: | ---: | ---: | ---: |
| full | 1.000 | 1.000 | 0.000 | 1.000 | 0.32 ms |
| static | 0.525 | 0.174 | 0.905 | 1.000 | <0.01 ms |
| no guard | 0.475 | 0.000 | 1.000 | 1.000 | <0.01 ms |

AgentGateBench has 31 cases and 40 decision points. It is a deterministic implementation and
ablation suite. The full score confirms fixture conformance only; it must not be used as evidence
of generalization.

## TS-Bench

Rules-only results over all 7,182 official records:

| Family | Cases | Accuracy | F1 | ASR | Benign completion | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| AgentDojo trajectories | 1,220 | 0.924 | 0.875 | 0.077 | 0.924 | 0.076 |
| AgentHarm | 731 | 1.000 | 1.000 | 0.000 | 1.000 | 0.000 |
| ASB | 5,231 | 0.607 | 0.367 | 0.764 | 0.955 | 0.045 |
| aggregate | 7,182 | 0.701 | 0.574 | 0.576 | 0.951 | 0.049 |

The aggregate is not the primary result because the families measure different security
questions. AgentDojo is the best external measure of the three runtime modules acting together.
AgentHarm validates the included task-policy categories; its tasks informed the deterministic
policy rules, so the perfect result is coverage evidence, not a held-out generalization result.

ASB shows the remaining research gap clearly. The deterministic path preserves benign tool
selection but cannot reliably align arbitrary tool names and rationales, producing a 76.4% ASR.
`CallSemanticRiskDetector` therefore exposes an optional LLM judge for this open-vocabulary case.
The legacy PACKY endpoint timed out before TLS connection. The configured SUB endpoint was later
validated with authenticated model listing, ordinary chat completion, and AgentGate's exact
`response_format=json_object` request using `gpt-5.5`. The full 5,231-case LLM-assisted ASB run
has not yet been executed, so no LLM-assisted benchmark score is reported here.

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
  --output artifacts/results/toolsafe-full.json
.venv/bin/python scripts/tune.py \
  --dataset benchmarks/agentgatebench/cases.jsonl \
  --output artifacts/results/tuning.json
```
