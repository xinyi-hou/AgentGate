from __future__ import annotations

import argparse
import subprocess
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXTERNAL = ROOT / "benchmarks" / "external"
TOOLSAFE_REVISION = "46358fa424a927a895c6c8322f99032c4eb5155e"
AGENTDOJO_REVISION = "089ed468cf3ed0322acc66b0211f26d9d90dbf60"

CANDIDATE_REPOSITORIES = {
    "injecagent": (
        "https://github.com/uiuc-kang-lab/InjecAgent.git",
        "f19c9f2c79a41046eb13c03c51a24c567a8ffa07",
    ),
    "toolemu": (
        "https://github.com/ryoungj/ToolEmu.git",
        "ac4a7ab7ed8c7985d96231e214bd6b54304b7ddb",
    ),
    "tau2-bench": (
        "https://github.com/sierra-research/tau2-bench.git",
        "1d244f5dca42944b67a379b44bfeb9f5748f189d",
    ),
    "mcp-safetybench": (
        "https://github.com/xjzzzzzzzz/MCPSafety.git",
        "7872437b6369aac1150e3a19e350a981dc554f81",
    ),
}

TOOLSAFE_FILES = (
    "agentdojo-traj/banking.json",
    "agentdojo-traj/slack.json",
    "agentdojo-traj/travel.json",
    "agentdojo-traj/workspace.json",
    "agentharm-traj/benign_steps.json",
    "agentharm-traj/harmful_steps.json",
    "asb-traj/test/DPI_attack_success.json",
    "asb-traj/test/OPI_attack_success.json",
    "asb-traj/test/atttack_failure.json",
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Fetch pinned AgentGate benchmark sources.")
    parser.add_argument(
        "--include-candidates",
        action="store_true",
        help="also fetch candidate suites that do not have AgentGate adapters yet",
    )
    return parser


def main() -> None:
    args = _parser().parse_args()
    _download_toolsafe()
    _checkout_repository(
        "agentdojo",
        "https://github.com/ethz-spylab/agentdojo.git",
        AGENTDOJO_REVISION,
    )
    if args.include_candidates:
        for name, (repository, revision) in CANDIDATE_REPOSITORIES.items():
            _checkout_repository(name, repository, revision)
    print(f"Benchmarks ready under {EXTERNAL}")


def _download_toolsafe() -> None:
    destination = EXTERNAL / "toolsafe" / "TS-Bench"
    for relative in TOOLSAFE_FILES:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            continue
        url = (
            "https://media.githubusercontent.com/media/MurrayTom/ToolSafe/"
            f"{TOOLSAFE_REVISION}/TS-Bench/{relative}"
        )
        print(f"Downloading {relative}")
        urllib.request.urlretrieve(url, target)


def _checkout_repository(name: str, repository: str, revision: str) -> None:
    destination = EXTERNAL / name
    if not destination.exists():
        subprocess.run(
            [
                "git",
                "clone",
                "--filter=blob:none",
                "--no-checkout",
                repository,
                str(destination),
            ],
            check=True,
        )
    subprocess.run(
        ["git", "-C", str(destination), "fetch", "--depth", "1", "origin", revision],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(destination), "checkout", "--detach", revision],
        check=True,
    )


if __name__ == "__main__":
    main()
