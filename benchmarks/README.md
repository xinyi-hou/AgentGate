# Benchmarks

AgentGate uses three complementary benchmarks rather than treating a high score on the local
fixture as sufficient evidence.

| Benchmark | Purpose | Integration |
| --- | --- | --- |
| AgentGateBench | executable integrity, authorization, and trajectory regression | native JSONL runner |
| TS-Bench | step-level safety decisions over task, history, environment, and candidate action | `evaluate-toolsafe` adapter |
| AgentDojo | end-to-end indirect prompt injection, attack success, and benign utility | `AgentDojoGuard` bridge |

AgentGateBench is intentionally deterministic and is used for implementation regression,
ablation, and policy tuning. Its current perfect score must not be reported as evidence of
generalization. TS-Bench and AgentDojo are the external evaluation gates.

Fetch the pinned upstream sources with:

```bash
.venv/bin/python scripts/fetch_benchmarks.py
```

Evaluate the downloaded TS-Bench data with:

```bash
.venv/bin/agentgate evaluate-toolsafe \
  --source benchmarks/external/toolsafe/TS-Bench \
  --output artifacts/results/toolsafe-full.json
```

The adapter reports metrics separately for:

- `agentdojo`: prompt-injection and task-effect decisions over recorded tool trajectories;
- `agentharm`: task-level enterprise safety policy decisions;
- `asb`: open-vocabulary attacker-tool selection, with optional LLM semantic alignment.

Do not report the aggregate alone. The three families have different labels and difficulty.

For model-family robustness, use the matrix runner. Sampling is stratified by upstream source and
selects complete interactions, so every model receives identical steps and reachable-trajectory
metrics remain valid:

```bash
.venv/bin/python scripts/evaluate_model_matrix.py \
  --source benchmarks/external/toolsafe/TS-Bench/asb-traj/test \
  --model gpt-5.4 \
  --model gemini-3.5-flash-lite \
  --model qwen3.5-4b-el \
  --sample-size 300 \
  --sample-seed 20260734 \
  --development-sample-size 30 \
  --development-sample-seed 20260728
```

The exact upstream revisions and licenses are recorded in `manifest.yaml`. External datasets
remain outside Git under `benchmarks/external/`.
