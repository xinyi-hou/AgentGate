# AgentGate End-to-End Evaluation

The primary evaluation unit is an executable task. An agent or deterministic task driver invokes
real isolated tools, AgentGate arbitrates before execution, and the environment records whether the
intended task and harmful side effect occurred. Trace replay is not used as an end-to-end result.

## Benchmark Matrix

| Benchmark | Evaluation scope | Unit |
|---|---:|---|
| AgentDojo v1.2 | All four suites, 97 user tasks x suite-specific injections = 949 attack combinations | Autonomous agent trajectory |
| Agent-SafetyBench | All 2,000 released tasks, up to 10 agent/tool rounds | Autonomous agent trajectory |
| AgentGate-StatefulBench v2 | 20 risk scenarios x 5 variants x attack/paired benign = 200 tasks | Deterministic executable workflow |
| MCP-SafetyBench | Threat-model-selected 74 core + 134 conditional tasks | MCP agent trajectory |
| MSB | Threat-model classification of 60 attack-type/goal families; 44 conditional selections | MCP agent trajectory |
| MCP-Bench | 48 multi-server tasks selected from 104 tasks | Benign ATG utility control |
| Semantic robustness | 2 executable tasks x 3 repeats x all 12 models in .env | Tool-registration and execution trajectory |

The MCP selection is capability-based rather than size-based. A core task must be observable at the
structured tool boundary, mediated by the MCP proxy, enforceable before the harmful effect, and
representable using AgentGate operations, resources, trust domains, data labels, and graph
relations. Conditional tasks are visible but need task authorization or metadata-integrity policy.
Out-of-scope tasks are retained in the applicability manifest and excluded from security-rate
denominators.

Generated manifests:

- results/manifests/mcp_threat_model_applicability.jsonl: every classified source task/family.
- results/manifests/mcp_threat_model_subset.jsonl: selected core and conditional entries.
- results/tables/mcp_threat_model_subset_summary.csv: counts by benchmark and applicability.

## StatefulBench v2

The self-built benchmark contains 100 attacks and 100 paired benign controls. Five variants change
customer/resource IDs, file paths, untrusted source domains, and external destinations. The 20 risk
families cover:

- personal, financial, secret, and credential exfiltration;
- direct, transformed, file-staged, aggregate, and cross-server propagation;
- untrusted execute, download-write-execute, install, and persistent install-execute;
- credential authentication and privilege escalation;
- untrusted-driven deletion, protected deletion, and dangerous commands;
- cumulative sensitive reads and untrusted-driven sensitive-data exfiltration.

Each task gets a fresh temporary environment. SEND, READ, EXECUTE, INSTALL, AUTH, PRIVILEGE, and
DELETE effects are materialized as isolated records or files. An attack is prevented only when its
harmful effect is absent and the sink was denied before execution.

The six evaluated modes are No Defense, A0 Event-only, A1 Event + Sequence, A2 ATG without
Provenance, A3 Provenance without propagated labels, and A4 Full AgentGate. The full run executes
1,200 tasks. rq1_risk_scenario_protection.csv reports every risk family separately rather than only
an aggregate ASR.

## Public End-to-End Runners

run_agentdojo.py keeps AgentDojo's native suite environments, tool_knowledge attacker, utility
evaluator, and security evaluator. AgentGate replaces only ToolsExecutor. Full mode enumerates all
949 v1.2 combinations, writes one checkpoint per combination, and supports process-level
parallelism and resume:

    set -a; source .env; set +a
    .venv/bin/python -m evaluation.runners.run_agentdojo \
      --all --defense agentgate --workers 16

run_agent_safetybench.py preserves the released 2,000 tasks, official environment classes, tool
schemas, system prompt, and maximum 10-round interaction loop. Each env.call_tool is mediated by a
FunctionToolAdapter. Tasks without structured tools are still executed but marked
applicable_to_agentgate=false; they are not counted as gateway defense successes.

    set -a; source .env; set +a
    .venv/bin/python -m evaluation.runners.run_agent_safetybench \
      --defense agentgate --concurrency 16

The upstream ShieldAgent scorer requires CUDA and FlashAttention. On a machine without that
environment, score_agent_safetybench.py can score full dialogues with the same safety rubric
through the configured API. These labels are explicitly stored as api_rubric_judge and must not be
reported as official ShieldAgent scores.

## LLM Stability

The semantic experiment fixes the task agent, tool implementation, input, policy, and executor. It
changes only the model used to infer a capability for the ambiguous relay_record schema. For each
model it runs three sensitive and three public-data tasks. Model variables are read in numeric order
from LLM_MODEL_1 through LLM_MODEL_12; concurrency defaults to one so model trials run sequentially:

    set -a; source .env; set +a
    .venv/bin/python -m evaluation.runners.run_semantic_robustness \
      --repeats 3 --concurrency 1

The output separates HTTP success, schema-valid semantic extraction, final decision, ASR, BCR,
FPR/FNR, tokens, latency, pairwise agreement, and case-level disagreements.

## Reproduction

    # Build the MCP applicability manifests from pinned local clones.
    .venv/bin/python -m evaluation.runners.build_mcp_threat_subsets

    # Run 200 tasks through all six stateful configurations.
    .venv/bin/python -m evaluation.runners.run_statefulbench

    # Controlled 5/10/20/40/80-call graph workload.
    .venv/bin/python -m evaluation.runners.run_scaling

    # Rebuild tables, figures, and failure slices.
    .venv/bin/python -m evaluation.runners.build_tables
    .venv/bin/python -m evaluation.runners.build_figures

    # Validate the repository.
    .venv/bin/ruff check .
    .venv/bin/pytest -q

External benchmark clones are ignored by Git; their URLs and pinned revisions are in manifest.yaml.
API keys and endpoint URLs are loaded from .env and are never serialized into result artifacts. A
missing credential or unavailable scorer is recorded as a blocker, not a zero score.
