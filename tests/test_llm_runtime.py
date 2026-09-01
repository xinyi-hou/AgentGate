from __future__ import annotations

import json

import httpx

from agentgate.semantics import OpenAICompatibleCompletion, OpenAICompatibleConfig


async def test_openai_compatible_completion_parses_structured_json() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/chat/completions"
        assert request.headers["authorization"] == "Bearer test-key"
        payload = json.loads(request.content)
        assert payload["model"] == "test-model"
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": '{"confidence": 0.9}'}}]},
        )

    completion = OpenAICompatibleCompletion(
        OpenAICompatibleConfig(
            base_url="https://gateway.test",
            api_key="test-key",
            model="test-model",
        ),
        transport=httpx.MockTransport(handler),
    )

    result = await completion(system_prompt="facts only", input_payload={"tool": "relay"})

    assert result == {"confidence": 0.9}


async def test_openai_compatible_completion_does_not_retry_invalid_schema() -> None:
    completion = OpenAICompatibleCompletion(
        OpenAICompatibleConfig(
            base_url="https://gateway.test",
            api_key="test-key",
            model="test-model",
        ),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json={"choices": [{"message": {"content": "not-json"}}]},
            )
        ),
    )

    try:
        await completion(system_prompt="facts only", input_payload={})
    except json.JSONDecodeError:
        pass
    else:
        raise AssertionError("invalid JSON must be rejected")

    assert completion.calls == 1
