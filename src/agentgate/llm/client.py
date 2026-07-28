from __future__ import annotations

import asyncio
import json
import re
import time
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
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.total_tokens = 0
        self.error_counts: dict[str, int] = {}
        self.last_error: str | None = None
        self.response_format_supported = True
        self.request_latencies_ms: list[float] = []

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
            "max_tokens": self.settings.llm_max_output_tokens,
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
        if self.response_format_supported:
            body["response_format"] = {"type": "json_object"}
        headers = {
            "Authorization": f"Bearer {self.settings.llm_api_key.get_secret_value()}",
            "Content-Type": "application/json",
        }
        attempts = self.settings.llm_max_retries + 1
        for attempt in range(attempts):
            self.request_count += 1
            started = time.perf_counter()
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
                response_data = response.json()
                self._record_usage(response_data.get("usage"))
                content = response_data["choices"][0]["message"]["content"]
                return _parse_json_object(content)
            except (httpx.HTTPError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                self._record_error(exc)
                if _response_format_is_unsupported(exc, body):
                    body.pop("response_format", None)
                    self.response_format_supported = False
                if attempt + 1 < attempts:
                    self.retry_count += 1
                    await asyncio.sleep(self.settings.llm_retry_backoff_seconds * (2**attempt))
                    continue
                self.failure_count += 1
                if self.settings.llm_fail_closed:
                    raise
                return None
            finally:
                self.request_latencies_ms.append((time.perf_counter() - started) * 1000)
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

    def stats(self) -> dict[str, Any]:
        latencies = sorted(self.request_latencies_ms)
        return {
            "requests": self.request_count,
            "retries": self.retry_count,
            "failures": self.failure_count,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "error_counts": dict(sorted(self.error_counts.items())),
            "last_error": self.last_error,
            "response_format_supported": self.response_format_supported,
            "mean_request_latency_ms": (
                sum(latencies) / len(latencies) if latencies else 0.0
            ),
            "request_latency_p50_ms": _percentile(latencies, 0.50),
            "request_latency_p95_ms": _percentile(latencies, 0.95),
            "request_latency_p99_ms": _percentile(latencies, 0.99),
            "max_request_latency_ms": max(latencies) if latencies else 0.0,
        }

    def _record_usage(self, usage: object) -> None:
        if not isinstance(usage, dict):
            return
        self.prompt_tokens += _non_negative_int(usage.get("prompt_tokens"))
        self.completion_tokens += _non_negative_int(usage.get("completion_tokens"))
        self.total_tokens += _non_negative_int(usage.get("total_tokens"))

    def _record_error(self, exc: Exception) -> None:
        if isinstance(exc, httpx.HTTPStatusError):
            error_type = f"http_{exc.response.status_code}"
            try:
                detail = str(exc.response.json().get("error", {}).get("message", ""))
            except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
                detail = exc.response.text
        else:
            error_type = type(exc).__name__
            detail = str(exc)
        self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1
        self.last_error = f"{error_type}: {detail[:240]}"


def _parse_json_object(content: str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(content, dict):
        return content
    text = content.strip()
    fenced = re.match(r"^```(?:json)?\s*(.*?)\s*```$", text, flags=re.DOTALL)
    if fenced:
        text = fenced.group(1)
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        value = _decode_embedded_json_object(text)
    if not isinstance(value, dict):
        raise ValueError("LLM response is not a JSON object")
    return value


def _decode_embedded_json_object(text: str) -> object:
    decoder = json.JSONDecoder()
    for index, character in enumerate(text):
        if character != "{":
            continue
        try:
            value, _ = decoder.raw_decode(text[index:])
            return value
        except json.JSONDecodeError:
            continue
    raise ValueError("LLM response does not contain a JSON object")


def _non_negative_int(value: object) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _percentile(values: list[float], quantile: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    position = (len(values) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(values) - 1)
    fraction = position - lower
    return values[lower] + (values[upper] - values[lower]) * fraction


def _response_format_is_unsupported(exc: Exception, body: dict[str, Any]) -> bool:
    if "response_format" not in body or not isinstance(exc, httpx.HTTPStatusError):
        return False
    if exc.response.status_code != 400:
        return False
    return "response_format" in exc.response.text.lower()
