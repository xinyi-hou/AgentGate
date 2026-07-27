from __future__ import annotations

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
        try:
            async with httpx.AsyncClient(
                timeout=self.settings.llm_timeout_seconds,
                transport=self.transport,
            ) as client:
                response = await client.post(
                    f"{self.settings.llm_base_url}/chat/completions", json=body, headers=headers
                )
                response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]
            return _parse_json_object(content)
        except (httpx.HTTPError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            if self.settings.llm_fail_closed:
                raise
            return None


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
