from __future__ import annotations

from ast import literal_eval
from collections.abc import Callable, Sequence
from typing import Any

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME
from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLMToolFilter
from agentdojo.agent_pipeline.tool_execution import is_string_list, tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionReturnType, FunctionsRuntime
from agentdojo.logging import Logger
from agentdojo.types import ChatMessage, ChatToolResultMessage, text_content_block_from_string

from evaluation.baselines import BaselineGuard, build_baseline_guard

_EMPTY_ENV = EmptyEnv()


class RecordingOpenAILLMToolFilter(OpenAILLMToolFilter):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.records: list[dict[str, Any]] = []

    def query(self, query, runtime, env=_EMPTY_ENV, messages=(), extra_args=None):
        before = len(runtime.functions)
        result = super().query(query, runtime, env, messages, extra_args or {})
        logger = Logger.get()
        context = getattr(logger, "context", {})
        self.records.append(
            {
                "suite_name": context.get("suite_name", "workspace"),
                "user_task_id": context.get("user_task_id", "unknown"),
                "injection_task_id": context.get("injection_task_id"),
                "tools_before": before,
                "tools_after": len(runtime.functions),
                "removed_tools": before - len(runtime.functions),
            }
        )
        return result


class RecordingToolsExecutor(BasePipelineElement):
    """AgentDojo executor with optional pre-call baseline mediation and call records."""

    def __init__(
        self,
        defense: str = "no_defense",
        tool_output_formatter: Callable[[FunctionReturnType], str] = tool_result_to_str,
    ) -> None:
        self.defense = defense
        self.output_formatter = tool_output_formatter
        self.records: list[dict[str, Any]] = []
        self._guards: dict[int, BaselineGuard | None] = {}

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = _EMPTY_ENV,
        messages: Sequence[ChatMessage] = (),
        extra_args: dict | None = None,
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        extra_args = extra_args or {}
        if not (
            messages
            and messages[-1]["role"] == "assistant"
            and messages[-1]["tool_calls"]
        ):
            return query, runtime, env, messages, extra_args
        guard = self._guard(query, runtime, env)
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
            decision = (
                guard.before_call(tool_call.function, dict(tool_call.args), tool_call.id)
                if guard is not None
                else None
            )
            executed = decision is None or decision.permits_execution
            if executed:
                output, error = runtime.run_function(
                    env,
                    tool_call.function,
                    tool_call.args,
                )
                success = error is None
                if guard is not None:
                    guard.after_call(
                        tool_call.function,
                        dict(tool_call.args),
                        tool_call.id,
                        output,
                    )
            else:
                output = ""
                error = f"{self.defense} BLOCK: {decision.reason}"
                success = None
            logger = Logger.get()
            context = getattr(logger, "context", {})
            self.records.append(
                {
                    "suite_name": context.get("suite_name", "workspace"),
                    "user_task_id": context.get("user_task_id", "unknown"),
                    "injection_task_id": context.get("injection_task_id"),
                    "call_id": tool_call.id,
                    "tool_name": tool_call.function,
                    "decision": decision.action if decision is not None else "ALLOW",
                    "rule_ids": list(decision.rule_ids) if decision is not None else [],
                    "executed": executed,
                    "success": success,
                }
            )
            results.append(
                ChatToolResultMessage(
                    role="tool",
                    content=[
                        text_content_block_from_string(self.output_formatter(output))
                    ],
                    tool_call_id=tool_call.id,
                    tool_call=tool_call,
                    error=error,
                )
            )
        return query, runtime, env, [*messages, *results], extra_args

    def _guard(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env,
    ) -> BaselineGuard | None:
        key = id(env)
        if key not in self._guards:
            descriptions = [
                {
                    "name": function.name,
                    "description": function.description,
                    "parameters": function.parameters.model_json_schema(),
                }
                for function in runtime.functions.values()
            ]
            self._guards[key] = build_baseline_guard(
                self.defense,
                descriptions,
                task_goal=query,
            )
        return self._guards[key]


def _error_result(tool_call, error: str) -> ChatToolResultMessage:
    return ChatToolResultMessage(
        role="tool",
        content=[text_content_block_from_string("")],
        tool_call_id=tool_call.id,
        tool_call=tool_call,
        error=error,
    )
