from __future__ import annotations

import argparse
import hashlib
import subprocess
from pathlib import Path
from urllib.request import urlopen

INJECAGENT_REVISION = "f19c9f2c79a41046eb13c03c51a24c567a8ffa07"
TOOLSAFE_REVISION = "46358fa424a927a895c6c8322f99032c4eb5155e"
TOOLSAFE_FILES = {
    "banking.json": "eb4a314845c8236ba1bbcd9855973f59279a70368b6eb31d447a4cd243086029",
    "slack.json": "08152de8cf9c39d01d58eb708f3a820a892f493841b975e09654ab904cf8a0d5",
    "travel.json": "1935121585fb1a02662e8121fe80e78c6d89b77e0c6035ea2b75b593e3728a22",
    "workspace.json": "74b20a4fcd7df1c3e39a231e64860aeac8cd57ce3531728b329080abbcc862d0",
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch pinned public evaluation datasets")
    parser.add_argument("--destination", type=Path, default=Path("benchmarks/external"))
    args = parser.parse_args()
    args.destination.mkdir(parents=True, exist_ok=True)
    _clone_injecagent(args.destination / "InjecAgent")
    _fetch_toolsafe(args.destination / "ToolSafe")


def _clone_injecagent(destination: Path) -> None:
    if destination.exists():
        revision = subprocess.run(
            ["git", "-C", str(destination), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if revision != INJECAGENT_REVISION:
            raise RuntimeError(f"unexpected InjecAgent revision: {revision}")
        return
    subprocess.run(
        ["git", "clone", "https://github.com/uiuc-kang-lab/InjecAgent.git", str(destination)],
        check=True,
    )
    subprocess.run(["git", "-C", str(destination), "checkout", INJECAGENT_REVISION], check=True)


def _fetch_toolsafe(destination: Path) -> None:
    target = destination / "TS-Bench" / "agentdojo-traj"
    target.mkdir(parents=True, exist_ok=True)
    for filename, expected_hash in TOOLSAFE_FILES.items():
        output = target / filename
        if not output.exists():
            url = (
                "https://media.githubusercontent.com/media/MurrayTom/ToolSafe/"
                f"{TOOLSAFE_REVISION}/TS-Bench/agentdojo-traj/{filename}"
            )
            with urlopen(  # noqa: S310 - fixed HTTPS origins and revisions
                url,
                timeout=60,
            ) as response:
                output.write_bytes(response.read())
        digest = hashlib.sha256(output.read_bytes()).hexdigest()
        if digest != expected_hash:
            raise RuntimeError(f"checksum mismatch for {output}: {digest}")


if __name__ == "__main__":
    main()
