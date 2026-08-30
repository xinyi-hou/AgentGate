# Evaluation

The evaluation separates security questions instead of reporting one mixed benchmark score.
InjecAgent measures deterministic detection of control instructions in tool results. The
AgentDojo-Traj split of TS-Bench measures pre-execution task authorization. Cross-call provenance
is covered by protocol-native mechanism tests because these public records do not preserve literal
value flow between tool results and later arguments.

```bash
.venv/bin/python scripts/fetch_benchmarks.py

.venv/bin/python -m agentgate.evaluation injecagent benchmarks/external/InjecAgent \
  --mode agentgate --output artifacts/results/injecagent-agentgate.json
.venv/bin/python -m agentgate.evaluation injecagent benchmarks/external/InjecAgent \
  --mode override_regex --output artifacts/results/injecagent-regex.json

.venv/bin/python -m agentgate.evaluation toolsafe benchmarks/external/ToolSafe \
  --mode agentgate --output artifacts/results/toolsafe-agentgate.json
.venv/bin/python -m agentgate.evaluation toolsafe benchmarks/external/ToolSafe \
  --mode static_acl --output artifacts/results/toolsafe-static-acl.json

.venv/bin/python -m agentgate.evaluation trajectory --mode agentgate \
  --output artifacts/results/trajectory-agentgate.json
.venv/bin/python -m agentgate.evaluation trajectory --mode stateless \
  --output artifacts/results/trajectory-stateless.json

.venv/bin/python -m agentgate.evaluation atg --mode full \
  --output artifacts/results/atg-full.json
.venv/bin/python -m agentgate.evaluation atg --mode no_provenance \
  --output artifacts/results/atg-no-provenance.json
.venv/bin/python -m agentgate.evaluation overhead \
  --output artifacts/results/atg-overhead.json

# Loads provider/model settings from .env. API keys are never written to the report.
# The default run evaluates only DeepSeek-V4-Pro-0813 (or LLM_DEFAULT_MODEL).
.venv/bin/python -m agentgate.evaluation llm evaluation/llm_capability_gold.yaml \
  --repeats 3 --output artifacts/results/llm-default.json

# Other numbered models are comparison subjects only.
.venv/bin/python -m agentgate.evaluation llm evaluation/llm_capability_gold.yaml \
  --stability --repeats 3 --timeout-seconds 45 --max-attempts 1 \
  --output artifacts/results/llm-stability.json
```

Unsafe examples are the positive class. Consequently, FPR is the fraction of benign examples
blocked and FNR is the fraction of unsafe examples allowed. Raw upstream datasets and generated
reports remain ignored by Git; revisions and retrieval logic are tracked.

The `atg` benchmark uses `AgentGateRuntime.execute`, candidate graph evaluation, and committed
RESULT deltas. Its positive prediction is a stateful graph/provenance/aggregate rule match; a
single-event approval without a graph relation is not counted as a graph positive. The LLM
benchmark holds the 24 tool declarations fixed across models and repetitions, uses temperature
zero, records schema failures and timeouts separately, and reports provider calls, token usage,
latency, exact-output stability, and accuracy conditioned on valid structured responses.
`--timeout-seconds` and `--max-attempts` bound remote-service tails; progress is emitted per model.
High concurrency is appropriate for offline experiments only.
