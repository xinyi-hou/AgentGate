from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import Sequence

from agentgate import __version__
from agentgate.adapters.mcp_transport import (
    McpJsonRpcUpstream,
    McpProtocolProxy,
    StdioJsonRpcUpstream,
    StreamableHttpJsonRpcUpstream,
    create_streamable_http_proxy_app,
    serve_stdio,
    static_context_provider,
)
from agentgate.policy.loader import load_policy
from agentgate.runtime import RuntimeContext, build_runtime


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

    mcp_stdio = commands.add_parser(
        "mcp-stdio",
        help="run a transparent MCP STDIO gateway in front of an upstream command",
    )
    _add_mcp_identity_arguments(mcp_stdio)
    mcp_stdio.add_argument("upstream_command", nargs=argparse.REMAINDER)

    mcp_http = commands.add_parser(
        "mcp-http",
        help="run a Streamable HTTP MCP gateway in front of an HTTP MCP server",
    )
    _add_mcp_identity_arguments(mcp_http)
    mcp_http.add_argument("--upstream-url", required=True)
    mcp_http.add_argument("--host", default="127.0.0.1")
    mcp_http.add_argument("--port", type=int, default=8081)
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
    if args.command == "mcp-stdio":
        command = list(args.upstream_command)
        if command[:1] == ["--"]:
            command = command[1:]
        asyncio.run(_serve_mcp_stdio(args, command))
        return 0
    if args.command == "mcp-http":
        import uvicorn

        runtime = build_runtime()
        transport = StreamableHttpJsonRpcUpstream(args.upstream_url)
        proxy = McpProtocolProxy(
            runtime,
            McpJsonRpcUpstream(transport),
            context_provider=static_context_provider(_mcp_context(args)),
        )
        uvicorn.run(
            create_streamable_http_proxy_app(proxy),
            host=args.host,
            port=args.port,
        )
        return 0
    return 2


def _add_mcp_identity_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--principal", required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--task-id")
    parser.add_argument("--agent-id")
    parser.add_argument("--authorization-id")


def _mcp_context(args: argparse.Namespace) -> RuntimeContext:
    return RuntimeContext(
        principal=args.principal,
        session_id=args.session_id,
        task_id=args.task_id,
        agent_id=args.agent_id,
        authorization_id=args.authorization_id,
    )


async def _serve_mcp_stdio(args: argparse.Namespace, command: list[str]) -> None:
    runtime = build_runtime()
    transport = StdioJsonRpcUpstream(command)
    proxy = McpProtocolProxy(
        runtime,
        McpJsonRpcUpstream(transport),
        context_provider=static_context_provider(_mcp_context(args)),
    )
    try:
        await serve_stdio(proxy)
    finally:
        await transport.aclose()
        await runtime.aclose()


if __name__ == "__main__":
    raise SystemExit(main())
