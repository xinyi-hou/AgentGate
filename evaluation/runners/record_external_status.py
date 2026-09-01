# ruff: noqa: E501

from __future__ import annotations

import argparse
from pathlib import Path

from evaluation.recording import git_revision, write_jsonl
from evaluation.schema import IntegrationFailure


def record_status(output_root: str | Path = "evaluation/results") -> None:
    root = Path(output_root)
    benchmark_metadata = [
        {
            "component": "AgentDojo",
            "repository": "https://github.com/ethz-spylab/agentdojo.git",
            "revision": git_revision("benchmarks/e2e/agentdojo"),
            "version": "0.1.35 / benchmark v1.2",
            "status": "executed_tool_effect_eligibility_and_matched_defense_trial",
            "scope": "609 effectful injection candidates and all 97 clean user tasks",
        },
        {
            "component": "Agent-SafetyBench",
            "repository": "https://github.com/thu-coai/Agent-SafetyBench.git",
            "revision": git_revision("benchmarks/e2e/agent_safetybench"),
            "version": "repository revision",
            "status": "executed_tool_effect_eligibility_and_matched_defense_trial",
            "scope": "346 structured-sink candidates and 234 same-sink authorized controls",
        },
        {
            "component": "MSB",
            "repository": "https://github.com/dongsenzhang/MSB.git",
            "revision": git_revision("benchmarks/e2e/msb"),
            "version": "mcp-use 1.3.7",
            "status": "integration_blocked",
            "scope": "prompt_injection / obtain_data_information preflight",
        },
        {
            "component": "MCP-SafetyBench",
            "repository": "https://github.com/xjzzzzzzzz/MCPSafety.git",
            "revision": git_revision("benchmarks/e2e/mcpsafety"),
            "version": "repository revision",
            "status": "paired_subset_built_execution_blocked",
            "scope": "74 core attacks and 74 attack-disabled paired controls",
        },
        {
            "component": "MCP-Bench",
            "repository": "https://github.com/Accenture/mcp-bench.git",
            "revision": git_revision("benchmarks/e2e/mcpbench"),
            "version": "repository revision",
            "status": "threat_model_subset_manifest_built",
            "scope": "48 multi-server benign utility controls; 56 single-server tasks excluded",
        },
        {
            "component": "AgentGate-StatefulBench",
            "repository": "local",
            "revision": git_revision(),
            "version": "4",
            "status": "executed_full",
            "scope": "24 risk scenarios x 5 variants x attack/paired benign x 8 modes",
        },
    ]
    write_jsonl(root / "normalized" / "benchmark_metadata.jsonl", benchmark_metadata)

    baseline_metadata = [
        {
            "component": "AgentDojo Tool Filter",
            "repository": "https://github.com/ethz-spylab/agentdojo.git",
            "revision": git_revision("benchmarks/e2e/agentdojo"),
            "version": "0.1.35",
            "status": "attempted_on_agentdojo_excluded_for_insufficient_completion",
            "adapter_modifications": ["recorded filtered tool sets and explicit run errors"],
        },
        {
            "component": "AgentSpec",
            "repository": "https://github.com/haoyuwang99/AgentSpec.git",
            "revision": git_revision("benchmarks/baselines/agentspec"),
            "version": "repository revision",
            "status": "executed_on_all_three_benchmarks",
            "adapter_modifications": [
                "mapped structured calls to official grammar trigger identifiers"
            ],
        },
        {
            "component": "Invariant Guardrails",
            "repository": "https://github.com/invariantlabs-ai/invariant.git",
            "revision": git_revision("benchmarks/baselines/invariant"),
            "version": "repository revision",
            "status": "executed_on_all_three_benchmarks",
            "adapter_modifications": ["pre-call LocalPolicy analyze_pending adapter"],
        },
        {
            "component": "MCPKernel",
            "repository": "https://github.com/piyushptiwari1/mcpkernel.git",
            "revision": git_revision("benchmarks/baselines/mcpkernel"),
            "version": "0.3.0",
            "status": "source_verified_not_integrated",
            "adapter_modifications": [],
        },
    ]
    write_jsonl(root / "normalized" / "baseline_metadata.jsonl", baseline_metadata)

    failures = [
        IntegrationFailure(
            component="MSB",
            repository="https://github.com/dongsenzhang/MSB.git",
            revision=git_revision("benchmarks/e2e/msb"),
            phase="executable_environment_connection",
            reason=(
                "The local filesystem MCP server started, but the required Paper Search MCP "
                "server redirected to interactive Smithery OAuth and waited for a browser callback."
            ),
            reproducible_command=(
                "source .env && benchmarks/e2e/msb/.venv-agentgate/bin/python -m "
                "evaluation.runners.run_msb --defense 'No Defense' "
                "--model-id DeepSeek-V4-Pro-0813"
            ),
            blocking_requirement="Non-interactive Smithery credentials for openags/paper-search-mcp.",
            metadata={
                "local_filesystem_server_started": True,
                "attack_side_effect_observed": False,
                "included_in_main_tables": False,
            },
        ),
        IntegrationFailure(
            component="MCP-SafetyBench",
            repository="https://github.com/xjzzzzzzzz/MCPSafety.git",
            revision=git_revision("benchmarks/e2e/mcpsafety"),
            phase="credential_and_isolation_preflight",
            reason=(
                "Of 74 core threat-model tasks, 50 require Google Maps, search, or a disposable "
                "GitHub identity. The remaining 24 financial/browser tasks contain real terminal "
                "and filesystem attack effects. Although Docker is present, this repository does "
                "not yet provide an AgentGate MCP proxy runner that disables the attack mutation "
                "for paired controls and records pre-effect ground truth."
            ),
            reproducible_command=(
                ".venv/bin/python -m evaluation.runners.build_mcp_threat_subsets"
            ),
            blocking_requirement=(
                "Scoped service keys for 50 tasks plus an end-to-end containerized AgentGate MCP "
                "adapter for all 74 attacks and their attack-disabled controls."
            ),
            metadata={
                "core_tasks": 74,
                "paired_controls": 74,
                "credential_free_core_candidates": 24,
                "included_in_effectiveness_denominator": False,
            },
        ),
        IntegrationFailure(
            component="MCP-Bench",
            repository="https://github.com/Accenture/mcp-bench.git",
            revision=git_revision("benchmarks/e2e/mcpbench"),
            phase="credential_preflight",
            reason=(
                "The selected 48 multi-server tasks require OpenRouter/Azure-compatible runner and "
                "judge configuration plus multiple server keys. The AgentGate .env only supplies "
                "the generic LLM endpoint; all benchmark-specific provider and server credentials "
                "are absent."
            ),
            reproducible_command="python run_benchmark.py --config config/benchmark_config.yaml",
            blocking_requirement="Benchmark provider, judge, and selected MCP server credentials.",
        ),
        IntegrationFailure(
            component="AgentGuard",
            repository="https://github.com/spkc83/agentguard.git",
            revision=git_revision("benchmarks/baselines/agentguard"),
            phase="baseline_adapter",
            reason=(
                "The public project exposes governance/RBAC integrations but no drop-in policy mapping "
                "for the pinned AgentDojo or StatefulBench tool contracts was supplied."
            ),
            blocking_requirement="A benchmark-blind policy and executable tool-boundary adapter.",
        ),
        IntegrationFailure(
            component="MCPKernel",
            repository="https://github.com/piyushptiwari1/mcpkernel.git",
            revision=git_revision("benchmarks/baselines/mcpkernel"),
            phase="baseline_adapter",
            reason=(
                "The proxy is applicable to MCP workloads, but the executable external MCP workloads "
                "were blocked at their own credential/OAuth preflights before a fair shared run."
            ),
            blocking_requirement="An executable credential-complete MCP benchmark workload.",
        ),
    ]
    write_jsonl(root / "failures" / "baseline_integration_failures.jsonl", failures)


def main() -> None:
    parser = argparse.ArgumentParser(description="Record pinned external evaluation status")
    parser.add_argument("--output-root", default="evaluation/results")
    args = parser.parse_args()
    record_status(args.output_root)


if __name__ == "__main__":
    main()
