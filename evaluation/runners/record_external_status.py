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
            "status": "executed_subset",
            "scope": "workspace user_task_0-1 x injection_task_0",
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
            "status": "not_run_missing_isolated_accounts",
            "scope": "real-world MCP servers",
        },
        {
            "component": "MCP-Bench",
            "repository": "https://github.com/Accenture/mcp-bench.git",
            "revision": git_revision("benchmarks/e2e/mcpbench"),
            "version": "repository revision",
            "status": "not_run_missing_provider_and_server_keys",
            "scope": "utility benchmark",
        },
        {
            "component": "AgentGate-StatefulBench",
            "repository": "local",
            "revision": git_revision(),
            "version": "1",
            "status": "executed_full",
            "scope": "8 attacks + 8 paired benign controls x 6 modes",
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
                "The benchmark performs real repository, filesystem, browser, and terminal actions. "
                "No dedicated disposable GitHub account and complete domain service credentials were provided."
            ),
            reproducible_command="PYTHONPATH=. python tests/benchmark/test_benchmark_repository_management.py",
            blocking_requirement=(
                "Dedicated test accounts, scoped service keys, Docker isolation, and disposable targets."
            ),
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
