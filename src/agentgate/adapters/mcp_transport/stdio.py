from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Sequence
from typing import Any

from .proxy import McpProtocolProxy
from .upstream import JsonObject


class StdioJsonRpcUpstream:
    def __init__(self, command: Sequence[str], *, environment: dict[str, str] | None = None):
        if not command:
            raise ValueError("an upstream MCP command is required")
        self.command = list(command)
        self.environment = environment
        self.process: asyncio.subprocess.Process | None = None
        self._pending: dict[str, asyncio.Future[JsonObject]] = {}
        self._write_lock = asyncio.Lock()
        self._reader_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        if self.process is not None:
            return
        self.process = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=sys.stderr,
            env=self.environment,
        )
        self._reader_task = asyncio.create_task(self._read_responses())

    async def request(self, message: JsonObject) -> JsonObject:
        await self.start()
        request_id = str(message["id"])
        future = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future
        await self._write(message)
        return await future

    async def notify(self, message: JsonObject) -> None:
        await self.start()
        await self._write(message)

    async def aclose(self) -> None:
        if self.process is None:
            return
        if self.process.stdin is not None:
            self.process.stdin.close()
            await self.process.stdin.wait_closed()
        try:
            await asyncio.wait_for(self.process.wait(), timeout=5)
        except TimeoutError:
            self.process.terminate()
            await self.process.wait()
        if self._reader_task is not None:
            await self._reader_task

    async def _write(self, message: JsonObject) -> None:
        assert self.process is not None and self.process.stdin is not None
        payload = json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n"
        async with self._write_lock:
            self.process.stdin.write(payload.encode())
            await self.process.stdin.drain()

    async def _read_responses(self) -> None:
        assert self.process is not None and self.process.stdout is not None
        while line := await self.process.stdout.readline():
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            request_id = message.get("id")
            future = self._pending.pop(str(request_id), None)
            if future is not None and not future.done():
                future.set_result(message)
        error = RuntimeError("upstream MCP STDIO transport closed")
        for future in self._pending.values():
            if not future.done():
                future.set_exception(error)
        self._pending.clear()


async def serve_stdio(proxy: McpProtocolProxy) -> None:
    """Serve an MCP JSON-RPC stream on this process's stdin/stdout."""
    while line := await asyncio.to_thread(sys.stdin.buffer.readline):
        try:
            message: dict[str, Any] = json.loads(line)
            response = await proxy.handle(message, {"x-agentgate-transport": "stdio"})
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            response = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": str(exc)},
            }
        if response is not None:
            rendered = json.dumps(response, ensure_ascii=False, separators=(",", ":"))
            await asyncio.to_thread(_write_stdout, rendered)


def _write_stdout(rendered: str) -> None:
    sys.stdout.write(f"{rendered}\n")
    sys.stdout.flush()
