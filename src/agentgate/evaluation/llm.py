from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from statistics import mean, pstdev
from typing import Any

import httpx
import yaml
from dotenv import load_dotenv

from agentgate.capabilities import CapabilityInferer, ToolCapability
from agentgate.semantics import SemanticResolution, StructuredSemanticResolver

from .metrics import _percentile


@dataclass(frozen=True)
class ProviderConfig:
    name: str
    model: str
    base_url: str
    api_key: str


@dataclass
class CompletionObservation:
    latency_ms: float
    input_tokens: int
    output_tokens: int
    total_tokens: int
    attempts: int


class OpenAICompatibleCompletion:
    def __init__(
        self,
        config: ProviderConfig,
        *,
        concurrency: int = 4,
        timeout_seconds: float = 120.0,
    ):
        self.config = config
        self.semaphore = asyncio.Semaphore(concurrency)
        self.client = httpx.AsyncClient(timeout=timeout_seconds)
        self.observations: list[CompletionObservation] = []
        self.provider_calls = 0
        self.http_errors = 0

    async def aclose(self) -> None:
        await self.client.aclose()

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
        async with self.semaphore:
            last_error: Exception | None = None
            for attempt in range(1, 4):
                self.provider_calls += 1
                started = time.perf_counter()
                try:
                    response = await self.client.post(
                        _chat_completions_url(self.config.base_url),
                        headers={"Authorization": f"Bearer {self.config.api_key}"},
                        json=request,
                    )
                    response.raise_for_status()
                    payload = response.json()
                    usage = payload.get("usage") or {}
                    latency_ms = (time.perf_counter() - started) * 1000
                    self.observations.append(
                        CompletionObservation(
                            latency_ms=latency_ms,
                            input_tokens=int(
                                usage.get("prompt_tokens", usage.get("input_tokens", 0)) or 0
                            ),
                            output_tokens=int(
                                usage.get("completion_tokens", usage.get("output_tokens", 0)) or 0
                            ),
                            total_tokens=int(usage.get("total_tokens", 0) or 0),
                            attempts=attempt,
                        )
                    )
                    content = payload["choices"][0]["message"]["content"]
                    if not isinstance(content, str):
                        raise ValueError("provider returned non-text structured content")
                    return _parse_json_object(content)
                except (
                    httpx.HTTPError,
                    KeyError,
                    TypeError,
                    ValueError,
                    json.JSONDecodeError,
                ) as exc:
                    last_error = exc
                    if isinstance(exc, httpx.HTTPStatusError):
                        self.http_errors += 1
                    if attempt < 3:
                        await asyncio.sleep(0.5 * attempt)
            assert last_error is not None
            raise last_error


async def evaluate_llm_capabilities(
    source: str | Path,
    *,
    model_names: list[str] | None = None,
    repeats: int = 3,
    concurrency: int = 4,
    env_file: str | Path = ".env",
) -> dict[str, Any]:
    load_dotenv(env_file, override=False)
    records = yaml.safe_load(Path(source).read_text(encoding="utf-8"))
    configs = _provider_configs()
    if model_names:
        selected = set(model_names)
        configs = [item for item in configs if item.model in selected or item.name in selected]
        missing = selected - {item.model for item in configs} - {item.name for item in configs}
        if missing:
            raise ValueError(f"unknown or unavailable model configurations: {sorted(missing)}")
    if not configs:
        raise RuntimeError("no configured LLM providers are available")

    outputs: list[dict[str, Any]] = []
    for config in configs:
        completion = OpenAICompatibleCompletion(config, concurrency=concurrency)
        resolver = StructuredSemanticResolver(completion)
        model_rows: list[dict[str, Any]] = []
        for repeat in range(1, repeats + 1):
            tasks = [_evaluate_record(resolver, record, repeat=repeat) for record in records]
            model_rows.extend(await asyncio.gather(*tasks))
        observations = completion.observations
        await completion.aclose()
        valid_rows = [row for row in model_rows if row["schema_valid"]]
        operation_scores = [row["operation_correct"] for row in model_rows]
        field_correct = sum(row["field_correct"] for row in model_rows)
        field_total = sum(row["field_total"] for row in model_rows)
        latencies = sorted(item.latency_ms for item in observations)
        case_rows: dict[str, list[dict[str, Any]]] = {}
        for row in model_rows:
            case_rows.setdefault(row["case_id"], []).append(row)
        stable_cases = sum(
            len(rows) == repeats
            and all(row["schema_valid"] for row in rows)
            and len({json.dumps(row["prediction"], sort_keys=True) for row in rows}) == 1
            for rows in case_rows.values()
        )
        operation_stable_cases = sum(
            len(rows) == repeats
            and all(row["schema_valid"] for row in rows)
            and len({row["prediction"]["operation"] for row in rows}) == 1
            for rows in case_rows.values()
        )
        repeat_operation_accuracy = [
            mean(row["operation_correct"] for row in model_rows if row["repeat"] == repeat)
            for repeat in range(1, repeats + 1)
        ]
        outputs.append(
            {
                "provider": config.name,
                "model": config.model,
                "repeats": repeats,
                "cases_per_repeat": len(records),
                "requests": len(model_rows),
                "provider_calls": completion.provider_calls,
                "http_success_responses": len(observations),
                "http_errors": completion.http_errors,
                "valid_requests": len(valid_rows),
                "request_success_rate": len(valid_rows) / len(model_rows),
                "schema_valid_rate": len(valid_rows) / len(model_rows),
                "operation_accuracy": sum(operation_scores) / len(operation_scores),
                "field_accuracy": field_correct / field_total if field_total else 0.0,
                "repeat_operation_accuracy": repeat_operation_accuracy,
                "repeat_accuracy_stddev": (
                    pstdev(repeat_operation_accuracy) if len(repeat_operation_accuracy) > 1 else 0.0
                ),
                "exact_match_rate": sum(
                    row["field_correct"] == row["field_total"] for row in model_rows
                )
                / len(model_rows),
                "stable_case_rate": stable_cases / len(records),
                "operation_stable_case_rate": operation_stable_cases / len(records),
                "input_tokens": sum(item.input_tokens for item in observations),
                "output_tokens": sum(item.output_tokens for item in observations),
                "total_tokens": sum(item.total_tokens for item in observations),
                "mean_tokens_per_request": (
                    mean(item.total_tokens for item in observations) if observations else 0.0
                ),
                "mean_latency_ms": mean(latencies) if latencies else 0.0,
                "p95_latency_ms": _percentile(latencies, 0.95),
                "retried_http_responses": sum(item.attempts > 1 for item in observations),
                "rows": model_rows,
            }
        )
    return {
        "benchmark": "AgentGate structured semantic resolver sensitivity",
        "temperature": 0,
        "repeats": repeats,
        "gold_cases": len(records),
        "rules_only": await evaluate_deterministic_capabilities(source),
        "models": outputs,
    }


async def evaluate_deterministic_capabilities(source: str | Path) -> dict[str, Any]:
    records = yaml.safe_load(Path(source).read_text(encoding="utf-8"))
    inferer = CapabilityInferer()
    rows: list[dict[str, Any]] = []
    latencies: list[float] = []
    for record in records:
        started = time.perf_counter()
        try:
            capability = await inferer.infer(
                name=record["name"],
                description=record["description"],
                input_schema=record.get("input_schema") or {},
                output_schema=record.get("output_schema") or {},
            )
        except Exception as exc:
            prediction = None
            error_type = type(exc).__name__
        else:
            prediction = _capability_dict(capability)
            error_type = None
        latencies.append((time.perf_counter() - started) * 1000)
        expected = record["expected"]
        correct, total = (
            score_capability_prediction(prediction, expected)
            if prediction is not None
            else (0, len(expected))
        )
        rows.append(
            {
                "case_id": record["id"],
                "prediction": prediction,
                "operation_correct": bool(
                    prediction and prediction["operation"] == expected["operation"]
                ),
                "field_correct": correct,
                "field_total": total,
                "error_type": error_type,
            }
        )
    return {
        "cases": len(rows),
        "valid_rate": sum(row["prediction"] is not None for row in rows) / len(rows),
        "operation_accuracy": sum(row["operation_correct"] for row in rows) / len(rows),
        "field_accuracy": sum(row["field_correct"] for row in rows)
        / sum(row["field_total"] for row in rows),
        "exact_match_rate": sum(row["field_correct"] == row["field_total"] for row in rows)
        / len(rows),
        "mean_latency_ms": mean(latencies),
        "p95_latency_ms": _percentile(sorted(latencies), 0.95),
        "rows": rows,
    }


async def _evaluate_record(
    resolver: StructuredSemanticResolver,
    record: dict[str, Any],
    *,
    repeat: int,
) -> dict[str, Any]:
    expected = record["expected"]
    try:
        resolution = await resolver.resolve(
            name=record["name"],
            description=record["description"],
            input_schema=record.get("input_schema") or {},
            output_schema=record.get("output_schema") or {},
            candidates=[],
            reason="evaluation_ambiguous_semantics",
        )
    except Exception as exc:  # Provider and schema errors are measured outcomes.
        status_code = exc.response.status_code if isinstance(exc, httpx.HTTPStatusError) else None
        return {
            "case_id": record["id"],
            "repeat": repeat,
            "schema_valid": False,
            "operation_correct": False,
            "field_correct": 0,
            "field_total": len(expected),
            "prediction": None,
            "error_type": type(exc).__name__,
            "error_status": status_code,
        }
    prediction = _resolution_dict(resolution)
    correct, total = score_capability_prediction(prediction, expected)
    return {
        "case_id": record["id"],
        "repeat": repeat,
        "schema_valid": True,
        "operation_correct": prediction["operation"] == expected["operation"],
        "field_correct": correct,
        "field_total": total,
        "prediction": prediction,
        "error_type": None,
        "error_status": None,
    }


def score_capability_prediction(
    prediction: dict[str, Any],
    expected: dict[str, Any],
) -> tuple[int, int]:
    correct = 0
    for key, expected_value in expected.items():
        actual_value = prediction.get(key)
        if isinstance(expected_value, list):
            matched = sorted(expected_value) == sorted(actual_value or [])
        else:
            matched = expected_value == actual_value
        correct += int(matched)
    return correct, len(expected)


def _resolution_dict(resolution: SemanticResolution) -> dict[str, Any]:
    return {
        "operation": resolution.operation.value if resolution.operation else None,
        "resource_type": resolution.resource_type.value if resolution.resource_type else None,
        "resource_arg": resolution.resource_arg,
        "scope_arg": resolution.scope_arg,
        "destination_arg": resolution.destination_arg,
        "payload_args": sorted(resolution.payload_args),
    }


def _capability_dict(capability: ToolCapability) -> dict[str, Any]:
    return {
        "operation": capability.possible_operations[0].value,
        "resource_type": capability.resource_type.value,
        "resource_arg": capability.resource_arg,
        "scope_arg": capability.scope_arg,
        "destination_arg": capability.destination_arg,
        "payload_args": sorted(capability.payload_args),
    }


def _provider_configs() -> list[ProviderConfig]:
    configs: list[ProviderConfig] = []
    _append_config(
        configs,
        name="openai-compatible-gpt",
        model_env="LLM_MODEL_GPT",
        base_env="SUB_URL",
        key_env="SUB_LLM_API",
    )
    for name, model_env, key_env in (
        ("packy-deepseek", "LLM_MODEL_DEEPSEEK_2", "PACKY_API_KEY_DEEPSEEK"),
        ("packy-glm", "LLM_MODEL_GLM_2", "PACKY_API_KEY_GLM"),
        ("packy-kimi", "LLM_MODEL_KIMI_2", "PACKY_API_KEY_KIMI"),
    ):
        _append_config(
            configs,
            name=name,
            model_env=model_env,
            base_env="PACKY_API_URL",
            key_env=key_env,
        )
    return configs


def _append_config(
    configs: list[ProviderConfig],
    *,
    name: str,
    model_env: str,
    base_env: str,
    key_env: str,
) -> None:
    model = os.getenv(model_env)
    base_url = os.getenv(base_env)
    api_key = os.getenv(key_env)
    if model and base_url and api_key:
        configs.append(ProviderConfig(name=name, model=model, base_url=base_url, api_key=api_key))


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
