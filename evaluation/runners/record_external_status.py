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
            "status": "full_end_to_end_runner",
            "scope": "all four suites; 949 tool_knowledge attack combinations",
        },
        {
            "component": "Agent-SafetyBench",
            "repository": "https://github.com/thu-coai/Agent-SafetyBench.git",
            "revision": git_revision("benchmarks/e2e/agent_safetybench"),
            "version": "repository revision",
            "status": "full_end_to_end_runner",
            "scope": "all 2,000 released tasks; AgentGate and matched No Defense",
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
            "status": "threat_model_subset_manifest_built",
            "scope": "74 core, 134 conditional, and 37 out-of-scope tasks",
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
            "version": "2",
            "status": "executed_full",
            "scope": "20 risk scenarios x 5 variants x attack/paired benign x 6 modes",
        },
    ]
    write_jsonl(root / "normalized" / "benchmark_metadata.jsonl", benchmark_metadata)

    baseline_metadata = [
        {
            "component": "AgentDojo Tool Filter",
            "repository": "https://github.com/ethz-spylab/agentdojo.git",
            "revision": git_revision("benchmarks/e2e/agentdojo"),
            "version": "0.1.35",
            "status": "executed_subset",
            "adapter_modifications": [
                "OpenAI-compatible provider name replaced by the fixed task model ID "
                "for the filter request; filtering policy is unchanged."
            ],
        },
        {
            "component": "AgentGuard",
            "repository": "https://github.com/spkc83/agentguard.git",
            "revision": git_revision("benchmarks/baselines/agentguard"),
            "version": "0.9.0",
            "status": "source_verified_not_integrated",
            "adapter_modifications": [],
        },
        {
            "component": "Invariant Guardrails",
            "repository": "https://github.com/invariantlabs-ai/invariant.git",
            "revision": git_revision("benchmarks/baselines/invariant"),
            "version": "repository revision",
            "status": "source_verified_not_integrated",
            "adapter_modifications": [],
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
                "and filesystem attack effects and require a validated disposable container adapter."
            ),
            reproducible_command=(
                ".venv/bin/python -m evaluation.runners.build_mcp_threat_subsets"
            ),
            blocking_requirement=(
                "Scoped service keys for 50 tasks and an end-to-end containerized gateway adapter "
                "for the 24 credential-free tasks."
            ),
            metadata={
                "core_tasks": 74,
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
                "The checked-in configuration requires OpenRouter/Azure model access, an LLM judge, "
                "and multiple MCP server API keys that are not present in the evaluation environment."
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
            component="Invariant Guardrails",
            repository="https://github.com/invariantlabs-ai/invariant.git",
            revision=git_revision("benchmarks/baselines/invariant"),
            phase="baseline_adapter",
            reason=(
                "The local analyzer accepts accumulated message traces; using it after execution would "
                "violate the pre-side-effect requirement. The separate Gateway was not configured."
            ),
            blocking_requirement="Invariant Gateway deployment plus benchmark-blind runtime policies.",
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
