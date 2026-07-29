# AgentGate Benchmark Strategy

## 1. Evaluation Rule

Benchmark text, labels, entity names, and attack templates must never become production rules.
Adapters may only convert upstream records into AgentGate's protocol-neutral objects:

```text
ToolSpec + ToolCall + TaskContract + typed external context
```

After conversion, every benchmark and every ablation must use the same module pipeline. Expected
labels are read only after the decision has been produced. A benchmark-specific parser is allowed
when the upstream format is unstructured, but any such parser must be reported and tested with
format perturbations.

The former AgentHarm phrase rules violated this requirement and have been removed. AgentHarm is no
longer treated as a rules-only generalization result.

## 2. Selected Suites

| Suite | Scale | Primary coverage | AgentGate use | Status |
| --- | ---: | --- | --- | --- |
| AgentGateBench | 216 paired scenarios / 306 decisions | deterministic runtime regression | all three security modules | integrated, not generalization evidence |
| TS-Bench | 7,182 recorded steps | step-level injection and call alignment | diagnostic semantic decisions | integrated with limitations |
| AgentDojo | 97 user tasks / 629 attack combinations | indirect prompt injection and utility | native module 1 plus end-to-end gateway | bridge exists; native run pending |
| InjecAgent | 1,054 cases, 17 user tools, 62 attacker tools | direct harm and data stealing after indirect injection | modules 1, 2, and cross-tool provenance | selected; adapter pending |
| ToolEmu | 144 cases / 36 toolkits | risky side effects in diverse tool domains | module 2 effects and module 3 post-result state | selected; adapter pending |
| tau2-bench | airline, retail, telecom, banking domains | task completion under explicit business policy | module 2 authorization and benign utility | selected; native interceptor pending |
| MCP-SafetyBench | 245 tasks / 20 attack types / 11 servers | poisoning, shadowing, return injection, replay, privilege misuse | all three modules over MCP | selected; isolated adapter pending |

Pinned sources and licenses are recorded in `benchmarks/manifest.yaml`. Fetch the currently
integrated sources with:

```bash
.venv/bin/python scripts/fetch_benchmarks.py
```

Fetch the selected but not yet integrated repositories with:

```bash
.venv/bin/python scripts/fetch_benchmarks.py --include-candidates
```

Downloading a repository does not make it an integrated benchmark and does not authorize running
its tools. In particular, MCP-SafetyBench can modify repositories and files. It must run in Docker
with dedicated test credentials and least-privilege service accounts.

## 3. Coverage by Research Module

| Security question | Primary suites | Required metrics |
| --- | --- | --- |
| Tool declaration and returned content contain manipulation | AgentDojo, InjecAgent, MCP-SafetyBench | injection ASR, clean utility, tool-poisoning recall/FPR |
| Call action, resource, scope, and effect match the task | TS-Bench ASB, ToolEmu, tau2-bench | call F1, unsafe-effect rate, policy violation rate, task success |
| A sequence creates cumulative or cross-tool harm | MCP-SafetyBench, ToolEmu, AgentDojo native trajectories | interaction ASR, source-to-sink violations, budget and replay detection |

Agent-SafetyBench and ControlArena/SHADE Arena remain secondary candidates. They broaden harmful
task and long-horizon sabotage coverage, but their model-policy and sandbox requirements add more
evaluation confounders than the four selected suites. They should be added only after the primary
adapters use a stable common event contract.

## 4. Anti-Overfitting Protocol

Before reporting a result:

1. freeze prompts, policy fields, thresholds, and tool-profile mappings before opening test labels;
2. select parameters only on a documented development split;
3. run exact-match scans between production strings and benchmark tasks;
4. apply paraphrase, tool rename, Schema-field rename, and injection-marker perturbations;
5. compare rules-only, semantic extraction, evidence fusion, and complete AgentGate on identical
   events;
6. report official benchmark metrics and AgentGate stop-on-deny metrics separately;
7. report parser failures, unknown tool profiles, LLM failures, and rule fallback counts;
8. do not use a benchmark for both policy construction and the final generalization claim.

The repository includes an executable exact-phrase audit for the integrated local suites:

```bash
.venv/bin/python scripts/audit_benchmark_leakage.py
```

Additional JSON/JSONL suites can be included with repeated `--benchmark PATH` arguments. The audit
checks production string constants, including regular-expression fragments, but deliberately
excludes tests, documentation, and evaluation adapters. Adapters need benchmark-specific format
markers to parse upstream records, but must not turn those markers or labels into decisions. The
audit is a leakage tripwire, not a substitute for adapter review, paraphrase testing, and
cross-suite evaluation.

The intended paper evidence is cross-suite consistency, not a single saturated score.
