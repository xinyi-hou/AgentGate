from __future__ import annotations

import asyncio
import json
import re
from typing import Any

import httpx

from agentgate.config import AgentGateSettings


class LLMAnalyzer:
    """Small OpenAI-compatible JSON analysis client used only for semantic extraction."""

    def __init__(
        self,
        settings: AgentGateSettings,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.settings = settings
        self.transport = transport
        self._client: httpx.AsyncClient | None = None
        self.request_count = 0
        self.retry_count = 0
        self.failure_count = 0

    @property
    def available(self) -> bool:
        return self.settings.llm_enabled and self.settings.llm_api_key is not None

    async def analyze_json(
        self,
        *,
        system_prompt: str,
        payload: dict[str, Any],
        schema_hint: dict[str, Any],
    ) -> dict[str, Any] | None:
        if not self.available:
            return None

        body = {
            "model": self.settings.llm_model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": json.dumps(
                        {"input": payload, "required_output": schema_hint}, ensure_ascii=False
                    ),
                },
            ],
        }
        headers = {
            "Authorization": f"Bearer {self.settings.llm_api_key.get_secret_value()}",
            "Content-Type": "application/json",
        }
        attempts = self.settings.llm_max_retries + 1
        for attempt in range(attempts):
            self.request_count += 1
            try:
                if self.transport is not None:
                    async with httpx.AsyncClient(
                        timeout=self.settings.llm_timeout_seconds,
                        transport=self.transport,
                    ) as client:
                        response = await client.post(
                            f"{self.settings.llm_base_url}/chat/completions",
                            json=body,
                            headers=headers,
                        )
                else:
                    response = await self._shared_client().post(
                        f"{self.settings.llm_base_url}/chat/completions",
                        json=body,
                        headers=headers,
                    )
                response.raise_for_status()
                content = response.json()["choices"][0]["message"]["content"]
                return _parse_json_object(content)
            except (httpx.HTTPError, KeyError, TypeError, ValueError, json.JSONDecodeError):
                if attempt + 1 < attempts:
                    self.retry_count += 1
                    await asyncio.sleep(self.settings.llm_retry_backoff_seconds * (2**attempt))
                    continue
                self.failure_count += 1
                if self.settings.llm_fail_closed:
                    raise
                return None
        return None

    def _shared_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.settings.llm_timeout_seconds,
                limits=httpx.Limits(max_connections=16, max_keepalive_connections=8),
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def stats(self) -> dict[str, int]:
        return {
            "requests": self.request_count,
            "retries": self.retry_count,
            "failures": self.failure_count,
        }


def _parse_json_object(content: str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(content, dict):
        return content
    text = content.strip()
    fenced = re.match(r"^```(?:json)?\s*(.*?)\s*```$", text, flags=re.DOTALL)
    if fenced:
        text = fenced.group(1)
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError("LLM response is not a JSON object")
    return value
