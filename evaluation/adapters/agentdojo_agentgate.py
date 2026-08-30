from __future__ import annotations

import asyncio
import hashlib
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
from agentgate.config import AgentGateSettings
from agentgate.events import ToolExecutionResult
from agentgate.runtime import RuntimeContext, build_runtime

_EMPTY_ENV = EmptyEnv()


class AgentGateToolsExecutor(BasePipelineElement):
    """Replace AgentDojo's tool executor while preserving its executable environment."""

    def __init__(
        self,
        audit_root: str | Path,
        tool_output_formatter: Callable[[FunctionReturnType], str] = tool_result_to_str,
    ) -> None:
        self.audit_root = Path(audit_root)
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
            )
        )
        adapter = FunctionToolAdapter(gateway)
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

            asyncio.run(
                adapter.register(
                    name=function.name,
                    executor=executor,
                    description=function.description,
                    input_schema=function.parameters.model_json_schema(),
                    output_schema=output_schema,
                )
            )
        context = RuntimeContext(
            principal="agentdojo-user",
            session_id=session,
            task_id=session,
            agent_id="agentdojo-agent",
        )
        created = (gateway, adapter, context)
        self._sessions[key] = created
        return created


def _requires_tool_execution(messages: Sequence[ChatMessage]) -> bool:
    return bool(messages and messages[-1]["role"] == "assistant" and messages[-1]["tool_calls"])


def _error_result(tool_call, error: str) -> ChatToolResultMessage:
    return ChatToolResultMessage(
        role="tool",
        content=[text_content_block_from_string("")],
        tool_call_id=tool_call.id,
        tool_call=tool_call,
        error=error,
    )
