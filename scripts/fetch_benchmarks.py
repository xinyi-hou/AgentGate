from __future__ import annotations

import subprocess
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXTERNAL = ROOT / "benchmarks" / "external"
TOOLSAFE_REVISION = "46358fa424a927a895c6c8322f99032c4eb5155e"
AGENTDOJO_REVISION = "089ed468cf3ed0322acc66b0211f26d9d90dbf60"

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


def main() -> None:
    _download_toolsafe()
    _clone_agentdojo()
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


def _clone_agentdojo() -> None:
    destination = EXTERNAL / "agentdojo"
    if not destination.exists():
        subprocess.run(
            [
                "git",
                "clone",
                "--filter=blob:none",
                "--no-checkout",
                "https://github.com/ethz-spylab/agentdojo.git",
                str(destination),
            ],
            check=True,
        )
    subprocess.run(
        ["git", "-C", str(destination), "fetch", "--depth", "1", "origin", AGENTDOJO_REVISION],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(destination), "checkout", "--detach", AGENTDOJO_REVISION],
        check=True,
    )


if __name__ == "__main__":
    main()
