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

LLM-assisted analysis is disabled by default. To enable the PACKY-compatible API, keep the
existing `.env` local and set `AGENTGATE_LLM_ENABLED=true`. `.env` is ignored by Git.

Run the sidecar with:

```bash
.venv/bin/uvicorn agentgate.runtime.api:app --host 127.0.0.1 --port 8080
```

The full artifact layout and benchmark workflow are documented in
[docs/artifact.md](docs/artifact.md).

## Current Reproduction Snapshot

The deterministic run on 2026-07-27 produced:

| Dataset | Accuracy | ASR | Benign completion |
| --- | ---: | ---: | ---: |
| AgentGateBench full | 100.0% | 0.0% | 100.0% |
| TS-Bench AgentDojo trajectories | 92.4% | 7.7% | 92.4% |
| TS-Bench AgentHarm policy set | 100.0% | 0.0% | 100.0% |
| TS-Bench ASB, rules only | 60.7% | 76.4% | 95.5% |

AgentGateBench is a regression fixture, and AgentHarm measures coverage of the included policy
families. Neither perfect result is a claim of out-of-distribution generalization. ASB is the
open-vocabulary tool-selection challenge intended for the optional LLM semantic judge. See
[docs/evaluation.md](docs/evaluation.md) for the full interpretation and commands.
