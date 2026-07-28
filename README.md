# AgentGate

AgentGate is a research artifact for a context-aware runtime security gateway between AI
agents and tools. It implements three independent security modules over a shared runtime:

1. tool semantic integrity modeling and context sanitization;
2. task-effect alignment and semantic authorization;
3. stateful information-flow and tool-trajectory control.

The repository includes a controlled 26-tool environment, an optional OpenAI-compatible LLM
analyzer, built-in and OPA policy backends, a FastAPI sidecar, an executable AgentGateBench,
and adapters for importing TS-Bench and integrating AgentDojo.

## Quick Start

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
.venv/bin/agentgate evaluate --dataset benchmarks/agentgatebench/cases.jsonl
```

LLM-assisted analysis is disabled by default. The runtime accepts generic `AGENTGATE_*`, `POE_*`,
`SUB_*`, or legacy `PACKY_*` OpenAI-compatible credentials in that precedence order. Keep `.env`
local and set `AGENTGATE_LLM_ENABLED=true` to enable semantic tool profiling, task-contract
extraction, evidence-based task-call alignment, result injection analysis, and semantic
sensitivity labels. The LLM extracts atomic facts; a deterministic evidence policy makes the
authorization decision. `.env` is ignored by Git.

Run the sidecar with:

```bash
.venv/bin/uvicorn agentgate.runtime.api:app --host 127.0.0.1 --port 8080
```

`POST /v1/contracts/build` converts a natural-language task into a least-privilege contract.
`POST /v1/calls/execute-task` builds that contract and evaluates the proposed call in one request.

The complete runtime design and implementation are documented in
[docs/system-implementation.md](docs/system-implementation.md). The artifact layout and benchmark
workflow are documented in [docs/artifact.md](docs/artifact.md). The cross-suite selection and
anti-overfitting protocol are documented in
[docs/benchmark-strategy.md](docs/benchmark-strategy.md).

## Current Reproduction Snapshot

The complete external run on 2026-07-28 produced:

| Dataset and view | Accuracy | ASR | Benign completion |
| --- | ---: | ---: | ---: |
| AgentGateBench full | 100.0% | 0.0% | 100.0% |
| TS-Bench AgentDojo trajectories, rules | 92.4% | 7.7% | 92.4% |
| TS-Bench AgentHarm, semantic policy disabled | 28.2% | 100.0% | 100.0% |
| TS-Bench ASB, generic call rules, official steps | 60.2% | 81.6% | 99.6% |
| TS-Bench ASB, historical direct verdict, official steps | 86.2% | 10.3% | 82.8% |
| TS-Bench ASB, historical direct verdict, reachable steps | 92.6% | 10.8% | 97.3% |

AgentGateBench is a regression fixture, not generalization evidence. The AgentHarm row is now a
negative control: after benchmark-derived phrase rules were removed, the non-LLM configuration
does not claim task-level harmfulness detection. The reachable view excludes recorded
continuations after the first gateway denial and is reported alongside, not instead of, the
official step-level result. See [docs/evaluation.md](docs/evaluation.md) for the methodology,
split results, LLM coverage, cost, and limitations.

A separate zero-interaction-overlap ASB sample compares GPT, Claude, Gemini, Qwen 4B, and a weak
Llama baseline under the new evidence-fusion design. Across GPT, Claude, Gemini, and Qwen 4B,
reachable F1 is 89.96%-91.70% and interaction ASR is 6.30%-8.66%; rules only reaches 20.00% F1 and
88.19% interaction ASR on the same sample. The weak Llama baseline reaches 82.61% F1 and 25.98%
interaction ASR, exposing the system's current model-capability floor instead of hiding it.
