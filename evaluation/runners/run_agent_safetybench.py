from __future__ import annotations

import argparse
import asyncio
import importlib.util
import json
import os
import sys
import time
from copy import deepcopy
from pathlib import Path
from typing import Any, Literal

from openai import AsyncOpenAI

from agentgate.adapters import FunctionToolAdapter
from agentgate.capabilities import CapabilityInferer, ToolCapability
from agentgate.config import AgentGateSettings
from agentgate.events import ResourceType, SecurityOperation, ToolExecutionResult
from agentgate.runtime import RuntimeContext, build_runtime
from agentgate.semantics import StructuredSemanticResolver
from evaluation.recording import git_revision, write_csv, write_jsonl

Defense = Literal["agentgate", "no_defense"]


class _SemanticCompletion:
    def __init__(self, client: AsyncOpenAI, model: str):
        self.client = client
        self.model = model

    async def __call__(self, *, system_prompt: str, input_payload: dict[str, Any]):
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(input_payload, sort_keys=True)},
            ],
            response_format={"type": "json_object"},
            temperature=0,
        )
        return json.loads(response.choices[0].message.content or "{}")


class _CapabilityCache:
    def __init__(self, client: AsyncOpenAI, model: str):
        self.inferer = CapabilityInferer(
            semantic_resolver=StructuredSemanticResolver(_SemanticCompletion(client, model))
        )
        self.cache: dict[str, ToolCapability] = {}
        self.inflight: dict[str, asyncio.Task[ToolCapability]] = {}
        self.lock = asyncio.Lock()

    async def resolve(self, description: dict[str, Any]) -> ToolCapability:
        key = json.dumps(description, ensure_ascii=True, sort_keys=True)
        async with self.lock:
            if key in self.cache:
                return self.cache[key]
            task = self.inflight.get(key)
            if task is None:
                task = asyncio.create_task(
                    self.inferer.infer(
                        name=description["name"],
                        description=description.get("description", ""),
                        input_schema=description.get("parameters", {}),
                        output_schema={},
                    )
                )
                self.inflight[key] = task
        try:
            capability = await task
        finally:
            async with self.lock:
                self.inflight.pop(key, None)
        async with self.lock:
            self.cache[key] = capability
        return capability


def _official_prompt(benchmark_root: Path) -> str:
    path = benchmark_root / "evaluation/model_api/BaseAPI.py"
    spec = importlib.util.spec_from_file_location("agent_safetybench_base_api", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load official prompt from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.BaseAPI().without_strict_jsonformat_sys_prompt


def _load_env_manager(benchmark_root: Path):
    environment_path = str((benchmark_root / "environments").resolve())
    if environment_path not in sys.path:
        sys.path.insert(0, environment_path)
    from EnvManager import EnvManager

    return EnvManager()


def _prepare_environments(case: dict[str, Any], env_manager) -> tuple[list[Any], list[dict]]:
    environments = []
    descriptions = []
    for info in case.get("environments", []):
        if not info.get("name"):
            continue
        environment = env_manager.init_env(info["name"], info.get("parameters") or None)
        if environment is None:
            raise RuntimeError(f"Cannot initialize Agent-SafetyBench env {info['name']}")
        environments.append(environment)
        descriptions.extend(deepcopy(environment.get_tool_descs(info["tools"])))
    return environments, descriptions


def _find_environment(
    environments: list[Any],
    tool_name: str,
) -> Any | None:
    for environment in environments:
        if environment.has_tool(tool_name):
            return environment
    return None


async def _completion(
    client: AsyncOpenAI,
    *,
    model: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    retries: int,
):
    error: Exception | None = None
    for attempt in range(retries + 1):
        try:
            return await client.chat.completions.create(
                model=model,
                messages=messages,
                tools=tools or None,
                temperature=0,
                max_tokens=2048,
            )
        except Exception as exc:
            error = exc
            if attempt < retries:
                await asyncio.sleep(min(4, 2**attempt))
    assert error is not None
    raise error


async def _run_case(
    case: dict[str, Any],
    *,
    client: AsyncOpenAI,
    model: str,
    defense: Defense,
    prompt: str,
    benchmark_root: Path,
    output_root: Path,
    env_manager: Any,
    capability_cache: _CapabilityCache,
    retries: int,
) -> dict[str, Any]:
    case_id = str(case["id"])
    checkpoint = (
        output_root
        / "checkpoints"
        / "agent_safetybench"
        / defense
        / model.replace("/", "_")
        / f"{case_id}.json"
    )
    if checkpoint.exists():
        return json.loads(checkpoint.read_text(encoding="utf-8"))

    started = time.perf_counter()
    environments, tool_descriptions = _prepare_environments(case, env_manager)
    tools = [{"type": "function", "function": item} for item in tool_descriptions]
    messages: list[dict[str, Any]] = [{"role": "system", "content": prompt}]
    messages.extend(deepcopy(case.get("dialog", [])))
    if "dialog" not in case:
        messages.append({"role": "user", "content": case["instruction"]})

    runtime = None
    adapter = None
    context = None
    decisions: list[dict[str, Any]] = []
    capability_failures: list[dict[str, str]] = []
    if defense == "agentgate" and tool_descriptions:
        audit_path = (
            output_root
            / "raw/agent_safetybench/audit"
            / model.replace("/", "_")
            / f"{case_id}.jsonl"
        )
        audit_path.unlink(missing_ok=True)
        runtime = build_runtime(
            AgentGateSettings(
                audit_path=audit_path,
                internal_domains={"internal.test", "company.test"},
            )
        )
        adapter = FunctionToolAdapter(runtime)
        context = RuntimeContext(
            principal="agent-safetybench-user",
            session_id=f"agent-safetybench-{case_id}",
            task_id=case_id,
            agent_id=f"{model}-agent",
        )
        registered: set[str] = set()
        for description in tool_descriptions:
            name = description["name"]
            if name in registered:
                continue
            registered.add(name)
            environment = _find_environment(environments, name)
            if environment is None:
                continue

            async def executor(arguments, env=environment, tool_name=name):
                result = await asyncio.to_thread(
                    env.call_tool,
                    tool_name,
                    deepcopy(arguments),
                )
                return ToolExecutionResult(output=result, success=True, affected_count=1)

            try:
                capability = await capability_cache.resolve(description)
            except Exception as exc:
                capability_failures.append(
                    {
                        "tool_name": name,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
                capability = ToolCapability(
                    tool_name=name,
                    possible_operations=[SecurityOperation.READ],
                    resource_type=ResourceType.UNKNOWN,
                )
            await adapter.register(name=name, capability=capability, executor=executor)

    rounds = 0
    status = "completed"
    error = ""
    try:
        while rounds < 10:
            completion = await _completion(
                client,
                model=model,
                messages=messages,
                tools=tools,
                retries=retries,
            )
            rounds += 1
            message = completion.choices[0].message
            if not message.tool_calls:
                if not (message.content or "").strip():
                    status = "empty_response"
                messages.append(
                    {
                        "role": "assistant",
                        "content": message.content or "",
                    }
                )
                break

            call = message.tool_calls[0]
            try:
                arguments = json.loads(call.function.arguments or "{}")
            except json.JSONDecodeError:
                arguments = {}
            messages.append(
                {
                    "role": "assistant",
                    "content": message.content,
                    "tool_calls": [
                        {
                            "id": call.id,
                            "type": "function",
                            "function": {
                                "name": call.function.name,
                                "arguments": json.dumps(arguments),
                            },
                        }
                    ],
                }
            )
            environment = _find_environment(
                environments,
                call.function.name,
            )
            if environment is None:
                result: Any = {
                    "success": False,
                    "message": f"Tool {call.function.name} doesn't exist.",
                }
            elif adapter is None or context is None:
                result = await asyncio.to_thread(
                    environment.call_tool,
                    call.function.name,
                    deepcopy(arguments),
                )
            else:
                outcome = await adapter.invoke(
                    tool_name=call.function.name,
                    arguments=arguments,
                    context=context,
                    call_id=call.id,
                    source_framework="agent-safetybench",
                    source_transport="in_process_executable",
                )
                decisions.append(
                    {
                        "round": rounds,
                        "call_id": call.id,
                        "tool_name": call.function.name,
                        "operation": outcome.request_event.operation.value,
                        "decision": outcome.decision.action.value,
                        "rule_ids": outcome.decision.rule_ids,
                        "executed": outcome.execution is not None,
                    }
                )
                if outcome.execution is None:
                    result = {
                        "success": False,
                        "message": (
                            f"AgentGate {outcome.decision.action.value}: "
                            + "; ".join(outcome.decision.reasons)
                        ),
                    }
                else:
                    result = outcome.execution.output
            messages.append(
                {
                    "role": "tool",
                    "content": json.dumps(result, ensure_ascii=False, default=str),
                    "tool_call_id": call.id,
                    "name": call.function.name,
                }
            )
        else:
            status = "max_rounds"
    except Exception as exc:
        status = "error"
        error = f"{type(exc).__name__}: {exc}"
    finally:
        if runtime is not None:
            await runtime.aclose()

    output = {
        **case,
        "output": messages,
        "_agentgate": {
            "benchmark": "Agent-SafetyBench",
            "benchmark_commit": git_revision(benchmark_root),
            "model": model,
            "defense": "AgentGate" if defense == "agentgate" else "No Defense",
            "status": status,
            "error": error,
            "rounds": rounds,
            "tool_calls": len(decisions)
            if defense == "agentgate"
            else sum("tool_calls" in message for message in messages),
            "blocked_calls": sum(not item["executed"] for item in decisions),
            "applicable_to_agentgate": bool(tool_descriptions),
            "applicability_reason": (
                "At least one structured tool call can be mediated."
                if tool_descriptions
                else "The task exposes no structured tool control point."
            ),
            "decisions": decisions,
            "capability_failures": capability_failures,
            "end_to_end_latency_ms": (time.perf_counter() - started) * 1000,
            "official_shield_label": None,
        },
    }
    checkpoint.parent.mkdir(parents=True, exist_ok=True)
    checkpoint.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    return output


def _write_summary(output_root: Path, records: list[dict[str, Any]]) -> None:
    defense = records[0]["_agentgate"]["defense"] if records else "unknown"
    grouped: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        risk = record["risks"][0]
        grouped.setdefault(risk, []).append(record)
    rows = []
    for risk, items in sorted(grouped.items()):
        metadata = [item["_agentgate"] for item in items]
        applicable = [item for item in metadata if item["applicable_to_agentgate"]]
        rows.append(
            {
                "risk": risk,
                "defense": defense,
                "tasks": len(items),
                "completed": sum(
                    item["status"] in {"completed", "max_rounds"} for item in metadata
                ),
                "applicable_tasks": len(applicable),
                "tasks_with_block": sum(item["blocked_calls"] > 0 for item in applicable),
                "blocked_calls": sum(item["blocked_calls"] for item in applicable),
                "official_shield_scored": sum(
                    item["official_shield_label"] is not None for item in metadata
                ),
            }
        )
    write_csv(
        output_root
        / "tables"
        / f"agent_safetybench_{defense.lower().replace(' ', '_')}_execution.csv",
        rows,
        [
            "risk",
            "defense",
            "tasks",
            "completed",
            "applicable_tasks",
            "tasks_with_block",
            "blocked_calls",
            "official_shield_scored",
        ],
    )


async def run_agent_safetybench(
    *,
    benchmark_root: str | Path,
    output_root: str | Path,
    model: str,
    defense: Defense,
    concurrency: int = 16,
    retries: int = 2,
    limit: int | None = None,
    case_ids: set[int] | None = None,
) -> list[dict[str, Any]]:
    benchmark_root = Path(benchmark_root).resolve()
    output_root = Path(output_root)
    cases = json.loads((benchmark_root / "data/released_data.json").read_text(encoding="utf-8"))
    if case_ids:
        cases = [case for case in cases if case["id"] in case_ids]
    if limit is not None:
        cases = cases[:limit]
    prompt = _official_prompt(benchmark_root)
    env_manager = _load_env_manager(benchmark_root)
    client = AsyncOpenAI(api_key=os.environ["LLM_API"], base_url=os.environ["LLM_URL"])
    capability_cache = _CapabilityCache(client, model)
    semaphore = asyncio.Semaphore(concurrency)
    completed = 0

    async def bounded(case):
        nonlocal completed
        async with semaphore:
            result = await _run_case(
                case,
                client=client,
                model=model,
                defense=defense,
                prompt=prompt,
                benchmark_root=benchmark_root,
                output_root=output_root,
                env_manager=env_manager,
                capability_cache=capability_cache,
                retries=retries,
            )
            completed += 1
            if completed % 50 == 0 or completed == len(cases):
                print(f"Agent-SafetyBench {defense}: {completed}/{len(cases)}")
            return result

    records = await asyncio.gather(*(bounded(case) for case in cases))
    await client.close()
    target = (
        output_root
        / "raw"
        / "agent_safetybench"
        / defense
        / model.replace("/", "_")
        / "gen_res.json"
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
    write_jsonl(
        output_root / "normalized" / f"agent_safetybench_{defense}.jsonl",
        [
            {
                "id": item["id"],
                "risks": item["risks"],
                "fulfillable": item["fulfillable"],
                **item["_agentgate"],
            }
            for item in records
        ],
    )
    _write_summary(output_root, records)
    return records


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run all Agent-SafetyBench tasks through the AgentGate execution boundary"
    )
    parser.add_argument(
        "--benchmark-root",
        default="benchmarks/e2e/agent_safetybench",
    )
    parser.add_argument("--output-root", default="evaluation/results")
    parser.add_argument("--model", default=os.getenv("LLM_MODEL_3", "DeepSeek-V4-Pro-0813"))
    parser.add_argument("--defense", choices=["agentgate", "no_defense"], default="agentgate")
    parser.add_argument("--concurrency", type=int, default=16)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--case-id", action="append", type=int, dest="case_ids")
    args = parser.parse_args()
    records = asyncio.run(
        run_agent_safetybench(
            benchmark_root=args.benchmark_root,
            output_root=args.output_root,
            model=args.model,
            defense=args.defense,
            concurrency=args.concurrency,
            retries=args.retries,
            limit=args.limit,
            case_ids=set(args.case_ids) if args.case_ids else None,
        )
    )
    print(f"completed {len(records)} Agent-SafetyBench tasks")


if __name__ == "__main__":
    main()
