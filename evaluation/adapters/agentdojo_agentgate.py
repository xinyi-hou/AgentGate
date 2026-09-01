from __future__ import annotations

import asyncio
import hashlib
import json
import os
from ast import literal_eval
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME
from agentdojo.agent_pipeline.tool_execution import is_string_list, tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionReturnType, FunctionsRuntime
from agentdojo.logging import Logger
from agentdojo.types import ChatMessage, ChatToolResultMessage, text_content_block_from_string
from pydantic import TypeAdapter

from agentgate.adapters import FunctionToolAdapter
from agentgate.capabilities import ToolCapability
from agentgate.config import AgentGateSettings
from agentgate.events import EffectType, SecurityOperation, ToolExecutionResult
from agentgate.runtime import RuntimeContext, build_runtime

_EMPTY_ENV = EmptyEnv()
_CAPABILITY_CACHE: dict[str, ToolCapability] = {}


class AgentGateToolsExecutor(BasePipelineElement):
    """Replace AgentDojo's tool executor while preserving its executable environment."""

    def __init__(
        self,
        audit_root: str | Path,
        model_id: str = "DeepSeek-V4-Pro-0813",
        capability_catalog: dict[str, dict[str, Any]] | None = None,
        tool_output_formatter: Callable[[FunctionReturnType], str] = tool_result_to_str,
    ) -> None:
        self.audit_root = Path(audit_root)
        self.model_id = model_id
        self.capability_catalog = {
            key: ToolCapability.model_validate(value)
            for key, value in (capability_catalog or {}).items()
        }
        self.output_formatter = tool_output_formatter
        self.records: list[dict[str, Any]] = []
        self._sessions: dict[int, tuple[Any, FunctionToolAdapter, RuntimeContext]] = {}

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = _EMPTY_ENV,
        messages: Sequence[ChatMessage] = (),
        extra_args: dict | None = None,
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        extra_args = extra_args or {}
        if not _requires_tool_execution(messages):
            return query, runtime, env, messages, extra_args
        gateway, adapter, context = self._session(query, runtime, env)
        del gateway
        results = []
        for tool_call in messages[-1]["tool_calls"] or []:
            if tool_call.function == EMPTY_FUNCTION_NAME:
                results.append(_error_result(tool_call, "Empty function name provided."))
                continue
            if tool_call.function not in runtime.functions:
                results.append(_error_result(tool_call, f"Invalid tool {tool_call.function}."))
                continue
            for key, value in tool_call.args.items():
                if isinstance(value, str) and is_string_list(value):
                    tool_call.args[key] = literal_eval(value)
            outcome = asyncio.run(
                adapter.invoke(
                    tool_name=tool_call.function,
                    arguments=dict(tool_call.args),
                    context=context,
                    call_id=tool_call.id,
                    source_framework="agentdojo",
                    source_transport="in_process_executable",
                )
            )
            executed = outcome.execution is not None
            error = None
            output: Any = ""
            if executed:
                output = outcome.execution.output
                error = outcome.execution.error_message
            else:
                reasons = "; ".join(outcome.decision.reasons)
                error = f"AgentGate {outcome.decision.action.value}: {reasons}"
            logger = Logger.get()
            context_data = getattr(logger, "context", {})
            self.records.append(
                {
                    "suite_name": context_data.get("suite_name", "workspace"),
                    "user_task_id": context_data.get("user_task_id", "unknown"),
                    "injection_task_id": context_data.get("injection_task_id"),
                    "call_id": tool_call.id,
                    "tool_name": tool_call.function,
                    "decision": outcome.decision.action.value,
                    "rule_ids": outcome.decision.rule_ids,
                    "executed": executed,
                    "success": outcome.execution.success if outcome.execution else None,
                }
            )
            results.append(
                ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string(self.output_formatter(output))],
                    tool_call_id=tool_call.id,
                    tool_call=tool_call,
                    error=error,
                )
            )
        return query, runtime, env, [*messages, *results], extra_args

    def _session(
        self,
        query: str,
        functions: FunctionsRuntime,
        env: Env,
    ) -> tuple[Any, FunctionToolAdapter, RuntimeContext]:
        key = id(env)
        existing = self._sessions.get(key)
        if existing is not None:
            return existing
        session = hashlib.sha256(f"{query}:{key}".encode()).hexdigest()[:16]
        gateway = build_runtime(
            AgentGateSettings(
                audit_path=self.audit_root / f"{session}.jsonl",
                internal_domains={"company.test", "internal.test"},
                llm_model=self.model_id,
                llm_timeout_seconds=float(
                    os.getenv("EVALUATION_LLM_TIMEOUT_SECONDS", "45")
                ),
                llm_max_attempts=1,
            )
        )
        adapter = FunctionToolAdapter(gateway)
        authorization = asyncio.run(
            gateway.authorize_task(
                principal="agentdojo-user",
                task_id=session,
                goal=query,
                entitlements={
                    "operations": [item.value for item in SecurityOperation],
                    "resources": ["*"],
                    "effects": [item.value for item in EffectType],
                    "destinations": ["*"],
                    "max_records": 100,
                },
                issuer="agentdojo-trusted-user-prompt",
            )
        )
        for function in functions.functions.values():
            output_schema: dict[str, Any] = {}
            if function.return_type is not None:
                try:
                    output_schema = TypeAdapter(function.return_type).json_schema()
                except (TypeError, ValueError):
                    output_schema = {}

            async def executor(arguments, name=function.name):
                result, error = functions.run_function(env, name, arguments)
                return ToolExecutionResult(
                    output=result,
                    success=error is None,
                    error_type="AgentDojoToolError" if error else None,
                    error_message=error,
                    affected_count=len(result) if isinstance(result, list) else 1,
                )

            input_schema = function.parameters.model_json_schema()
            capability_key = _capability_cache_key(
                function.name,
                function.description,
                input_schema,
                output_schema,
            )
            capability = self.capability_catalog.get(capability_key)
            if capability is None:
                capability = _CAPABILITY_CACHE.get(capability_key)
            if capability is None:
                capability = asyncio.run(
                    adapter.inferer.infer(
                        name=function.name,
                        description=function.description,
                        input_schema=input_schema,
                        output_schema=output_schema,
                    )
                )
                _CAPABILITY_CACHE[capability_key] = capability
            asyncio.run(
                adapter.register(
                    name=function.name,
                    executor=executor,
                    capability=capability,
                )
            )
        context = RuntimeContext(
            principal="agentdojo-user",
            session_id=session,
            task_id=session,
            agent_id="agentdojo-agent",
            authorization_id=authorization.authorization_id,
        )
        created = (gateway, adapter, context)
        self._sessions[key] = created
        return created


def _requires_tool_execution(messages: Sequence[ChatMessage]) -> bool:
    return bool(messages and messages[-1]["role"] == "assistant" and messages[-1]["tool_calls"])


def _capability_cache_key(
    name: str,
    description: str,
    input_schema: dict[str, Any],
    output_schema: dict[str, Any],
) -> str:
    payload = {
        "capability_classifier_version": 2,
        "name": name,
        "description": description,
        "input_schema": input_schema,
        "output_schema": output_schema,
    }
    rendered = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(rendered.encode()).hexdigest()


def warm_capability_catalog(
    functions: Sequence[Any],
    *,
    model_id: str,
    cache_path: str | Path,
) -> dict[str, dict[str, Any]]:
    """Resolve each suite tool once before process-level task parallelism."""
    path = Path(cache_path)
    catalog: dict[str, dict[str, Any]] = {}
    if path.exists():
        stored = json.loads(path.read_text(encoding="utf-8"))
        if stored.get("model_id") == model_id:
            catalog = stored.get("capabilities", {})
    gateway = build_runtime(
        AgentGateSettings(
            audit_path=path.with_suffix(".audit.jsonl"),
            internal_domains={"company.test", "internal.test"},
            llm_model=model_id,
            llm_timeout_seconds=float(os.getenv("EVALUATION_LLM_TIMEOUT_SECONDS", "45")),
            llm_max_attempts=1,
        )
    )
    for function in functions:
        output_schema: dict[str, Any] = {}
        if function.return_type is not None:
            try:
                output_schema = TypeAdapter(function.return_type).json_schema()
            except (TypeError, ValueError):
                output_schema = {}
        input_schema = function.parameters.model_json_schema()
        key = _capability_cache_key(
            function.name,
            function.description,
            input_schema,
            output_schema,
        )
        if key in catalog:
            continue
        capability = asyncio.run(
            gateway.capability_inferer.infer(
                name=function.name,
                description=function.description,
                input_schema=input_schema,
                output_schema=output_schema,
            )
        )
        catalog[key] = capability.model_dump(mode="json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {"model_id": model_id, "capabilities": catalog},
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
    asyncio.run(gateway.aclose())
    return catalog


def _error_result(tool_call, error: str) -> ChatToolResultMessage:
    return ChatToolResultMessage(
        role="tool",
        content=[text_content_block_from_string("")],
        tool_call_id=tool_call.id,
        tool_call=tool_call,
        error=error,
    )
