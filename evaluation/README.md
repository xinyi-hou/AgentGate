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
```

Unsafe examples are the positive class. Consequently, FPR is the fraction of benign examples
blocked and FNR is the fraction of unsafe examples allowed. Raw upstream datasets and generated
reports remain ignored by Git; revisions and retrieval logic are tracked.
