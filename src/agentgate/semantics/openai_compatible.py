from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any

import httpx


@dataclass(frozen=True)
class OpenAICompatibleConfig:
    base_url: str
    api_key: str
    model: str


class OpenAICompatibleCompletion:
    """Small provider-neutral JSON completion client used by runtime resolvers."""

    def __init__(
        self,
        config: OpenAICompatibleConfig,
        *,
        timeout_seconds: float = 120.0,
        max_attempts: int = 3,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        if timeout_seconds <= 0 or max_attempts < 1:
            raise ValueError("timeout_seconds and max_attempts must be positive")
        self.config = config
        self.timeout_seconds = timeout_seconds
        self.max_attempts = max_attempts
        self.transport = transport
        self.calls = 0
        self.failures = 0

    async def __call__(
        self,
        *,
        system_prompt: str,
        input_payload: dict[str, Any],
    ) -> dict[str, Any]:
        request = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": json.dumps(input_payload, ensure_ascii=False, sort_keys=True),
                },
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0,
            "max_tokens": 4096,
        }
        last_error: Exception | None = None
        for attempt in range(1, self.max_attempts + 1):
            self.calls += 1
            try:
                async with httpx.AsyncClient(
                    timeout=self.timeout_seconds,
                    transport=self.transport,
                ) as client:
                    response = await client.post(
                        _chat_completions_url(self.config.base_url),
                        headers={"Authorization": f"Bearer {self.config.api_key}"},
                        json=request,
                    )
                response.raise_for_status()
                content = response.json()["choices"][0]["message"]["content"]
                if not isinstance(content, str):
                    raise ValueError("provider returned non-text structured content")
                return _parse_json_object(content)
            except (httpx.HTTPError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                last_error = exc
                self.failures += 1
                if attempt < self.max_attempts and _retryable_error(exc):
                    await asyncio.sleep(0.5 * attempt)
                    continue
                break
        assert last_error is not None
        raise last_error

    async def aclose(self) -> None:
        # A client is scoped to each request so the completion can safely be used by
        # synchronous framework bridges that create a new event loop per invocation.
        return None


def _chat_completions_url(base_url: str) -> str:
    base = base_url.rstrip("/")
    if not base.endswith("/v1"):
        base += "/v1"
    return f"{base}/chat/completions"


def _parse_json_object(content: str) -> dict[str, Any]:
    rendered = content.strip()
    if rendered.startswith("```"):
        lines = rendered.splitlines()
        rendered = "\n".join(lines[1:-1]).strip()
    parsed = json.loads(rendered)
    if not isinstance(parsed, dict):
        raise ValueError("structured completion must be a JSON object")
    return parsed


def _retryable_error(exc: Exception) -> bool:
    if isinstance(exc, (httpx.ConnectError, httpx.TimeoutException)):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in {408, 409, 429} or exc.response.status_code >= 500
    return False
