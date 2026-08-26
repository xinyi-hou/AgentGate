from __future__ import annotations

import argparse
import json
from collections.abc import Sequence

from agentgate import __version__
from agentgate.policy.loader import load_policy


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentgate",
        description="Stateful runtime security gateway for agent tool calls",
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    serve = commands.add_parser("serve", help="run the HTTP sidecar")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)

    policy = commands.add_parser("policy-check", help="validate and render a policy file")
    policy.add_argument("path", nargs="?")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "serve":
        import uvicorn

        uvicorn.run("agentgate.api.app:app", host=args.host, port=args.port)
        return 0
    if args.command == "policy-check":
        policy = load_policy(args.path)
        print(json.dumps(policy.model_dump(mode="json"), ensure_ascii=False, indent=2))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
