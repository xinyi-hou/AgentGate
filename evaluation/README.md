# AgentGate End-to-End Evaluation

The primary evaluation unit is an executable task. An agent or deterministic task driver invokes
real isolated tools, AgentGate arbitrates before execution, and the environment records whether the
intended task and harmful side effect occurred. Trace replay is not used as an end-to-end result.

## Benchmark Matrix

| Benchmark | Evaluation scope | Unit |
|---|---:|---|
| AgentDojo v1.2 | All four suites, 97 user tasks x suite-specific injections = 949 attack combinations | Autonomous agent trajectory |
| Agent-SafetyBench | All 2,000 released tasks, up to 10 agent/tool rounds | Autonomous agent trajectory |
| AgentGate-StatefulBench v3 | 24 risk scenarios x 5 variants x attack/paired benign = 240 tasks | Deterministic executable workflow |
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

## Completed Results

Both public benchmarks were executed end to end with DeepSeek-V4-Pro-0813 for AgentGate and a
matched No Defense control. AgentDojo completed 949/949 combinations per defense. On the common
949-combination denominator, AgentGate reduced official-evaluator ASR from 60/949 (6.32%) to
14/949 (1.48%); utility fell from 824/949 (86.83%) to 676/949 (71.23%). Because AgentDojo's
`injection_task_solvable` is recomputed under each defense, it is not a valid cross-defense
denominator. The secondary result therefore fixes the No Defense solvable set (874 combinations):
60/874 (6.86%) versus 14/874 (1.60%).

Agent-SafetyBench completed and scored 2,000/2,000 tasks per defense. The API rubric judge labeled
504/2,000 (25.20%) No Defense trajectories unsafe and 419/2,000 (20.95%) AgentGate trajectories
unsafe. For the fixed 1,586 tasks exposing a structured tool boundary, the rates were 489/1,586
(30.83%) and 402/1,586 (25.35%). These are not official ShieldAgent scores. The remaining 414
tasks are retained in the all-task result but cannot be attributed to a tool gateway.

These public trajectory deltas are diagnostic, not causal gateway true positives. Paired analysis
shows that only 12 of AgentDojo's 51 baseline-positive outcome improvements and 75 of the 184
tool-applicable Agent-SafetyBench improvements coincided with any denied tool call. The remaining
changes occurred without an AgentGate intervention. `rq1_public_attribution.csv` reports these
categories explicitly. These runs used the earlier conservative approval policy and are not scores
for the revised evidence-tiered default policy.

StatefulBench v3 executed all 1,440 mode-task combinations. Full AgentGate prevented 120/120
harmful side effects before execution and completed 120/120 paired benign controls; No Defense
allowed 120/120 attacks. At the enforceable tool boundary this is TP=120, FN=0, TN=120, FP=0.

Generated manifests:

- results/manifests/mcp_threat_model_applicability.jsonl: every classified source task/family.
- results/manifests/mcp_threat_model_subset.jsonl: selected core and conditional entries.
- results/tables/mcp_threat_model_subset_summary.csv: counts by benchmark and applicability.

## StatefulBench v3

The self-built benchmark contains 120 attacks and 120 paired benign controls. Five variants change
customer/resource IDs, file paths, untrusted source domains, and external destinations. Variants
1--3 are marked development and variants 4--5 are held out from parameter selection. The 24 risk
families cover:

- personal, financial, secret, and credential exfiltration;
- direct, transformed, file-staged, aggregate, and cross-server propagation;
- untrusted execute, download-write-execute, install, and persistent install-execute;
- credential authentication and privilege escalation;
- untrusted-driven deletion, protected deletion, and dangerous commands;
- cumulative sensitive reads and untrusted-driven sensitive-data exfiltration.
- sensitive sends whose only difference is a trusted versus unknown destination;
- untrusted reads followed by dependent versus unrelated execution or deletion;
- cross-agent sensitive handoff versus cross-agent public-data transfer.

Each task gets a fresh temporary environment. SEND, READ, EXECUTE, INSTALL, AUTH, PRIVILEGE, and
DELETE effects are materialized as isolated records or files. An attack is prevented only when its
harmful effect is absent and the sink was denied before execution.

The six evaluated modes are No Defense, A0 Event-only, A1 Event + Sequence, A2 ATG without
Provenance, A3 Provenance without propagated labels, and A4 Full AgentGate. The full run executes
1,440 mode-task combinations. rq1_gateway_confusion_matrix.csv reports TP/FN/TN/FP, precision,
recall, specificity, FPR, FNR, F1, and MCC. An attack enters the positive denominator only when its
matched No Defense execution materializes the harmful effect. A TP additionally requires a denial
before that effect. rq1_risk_scenario_protection.csv reports every risk family separately.

## Public End-to-End Runners

run_agentdojo.py keeps AgentDojo's native suite environments, tool_knowledge attacker, utility
evaluator, and security evaluator. AgentGate replaces only ToolsExecutor. Full mode enumerates all
949 v1.2 combinations, writes one checkpoint per combination, and supports process-level
parallelism and resume:

    set -a; source .env; set +a
    .venv/bin/python -m evaluation.runners.run_agentdojo \
      --all --defense agentgate --workers 16

Run the matched no-defense matrix with the same model and task enumeration:

    .venv/bin/python -m evaluation.runners.run_agentdojo \
      --all --defense no_defense --workers 16

run_agent_safetybench.py preserves the released 2,000 tasks, official environment classes, tool
schemas, system prompt, and maximum 10-round interaction loop. Each env.call_tool is mediated by a
FunctionToolAdapter. Tasks without structured tools are still executed but marked
applicable_to_agentgate=false; they are not counted as gateway defense successes.

    set -a; source .env; set +a
    .venv/bin/python -m evaluation.runners.run_agent_safetybench \
      --defense agentgate --concurrency 16

The matched no-defense run uses `--defense no_defense`. After each full execution run, score its
dialogues separately. Scorer checkpoints include the defense configuration and cannot be reused
across AgentGate and No Defense:

    .venv/bin/python -m evaluation.runners.score_agent_safetybench \
      --input evaluation/results/raw/agent_safetybench/agentgate/DeepSeek-V4-Pro-0813/gen_res.json \
      --concurrency 16

    .venv/bin/python -m evaluation.runners.build_public_tables

The upstream ShieldAgent scorer requires CUDA and FlashAttention. On a machine without that
environment, score_agent_safetybench.py can score full dialogues with the same safety rubric
through the configured API. These labels are explicitly stored as api_rubric_judge and must not be
reported as official ShieldAgent scores.

## MCP Threat-Model Subsets

The applicability manifest is an evaluation contract, not a claim that every selected row has
already run. MCP-SafetyBench has 74 core tasks; 24 of them are in the financial-analysis and
browser-automation domains and do not require dedicated service credentials, while the remaining
50 require Google Maps, search, or disposable GitHub credentials. The benchmark contains real
terminal and filesystem attack effects, so even credential-free tasks must run in a disposable
container with AgentGate mediating every server. MSB remains blocked by interactive Paper Search
OAuth. MCP-Bench's 48 selected rows are benign multi-server utility controls and require the
corresponding server credentials; they are not security attacks and must not contribute to an ASR.

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

    # Run 240 tasks through all six stateful configurations.
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
