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
from agentgate.events import (
    EffectType,
    ResourceType,
    SecurityOperation,
    ToolExecutionResult,
)
from agentgate.runtime import RuntimeContext, build_runtime
from agentgate.semantics import StructuredSemanticResolver
from evaluation.baselines import build_baseline_guard
from evaluation.recording import git_revision, write_csv, write_jsonl

Defense = Literal["agentgate", "no_defense", "agentspec", "invariant"]

DEFENSE_LABELS = {
    "agentgate": "AgentGate",
    "no_defense": "No Defense",
    "agentspec": "AgentSpec",
    "invariant": "Invariant Guardrails",
}


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
        self.failures: dict[str, Exception] = {}
        self.inflight: dict[str, asyncio.Task[ToolCapability]] = {}
        self.lock = asyncio.Lock()

    async def resolve(self, description: dict[str, Any]) -> ToolCapability:
        key = json.dumps(description, ensure_ascii=True, sort_keys=True)
        async with self.lock:
            if key in self.cache:
                return self.cache[key]
            if key in self.failures:
                raise self.failures[key]
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
        except Exception as exc:
            async with self.lock:
                self.failures[key] = exc
            raise
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


def _trusted_task_goal(case: dict[str, Any]) -> str:
    if "instruction" in case:
        return str(case["instruction"])
    return "\n".join(
        str(message.get("content", ""))
        for message in case.get("dialog", [])
        if message.get("role") == "user"
    )


def _find_environment(
    environments: list[Any],
    tool_name: str,
) -> Any | None:
    for environment in environments:
        if environment.has_tool(tool_name):
            return environment
    return None


def _call_environment_tool(
    environment: Any,
    tool_name: str,
    arguments: dict[str, Any],
) -> Any:
    try:
        return environment.call_tool(tool_name, deepcopy(arguments))
    except Exception as exc:
        # Some released fixtures contain records that do not match their own
        # tool schema. Preserve the failed tool turn instead of dropping the
        # complete benchmark trajectory.
        return {
            "success": False,
            "message": f"Environment tool error: {type(exc).__name__}: {exc}",
        }


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
                delay = 60 if type(exc).__name__ == "RateLimitError" else min(4, 2**attempt)
                await asyncio.sleep(delay)
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
    run_tag: str,
) -> dict[str, Any]:
    case_id = str(case.get("_evaluation", {}).get("case_id", case["id"]))
    checkpoint_name = case_id.replace("::", "__").replace("/", "_")
    checkpoint = (
        output_root
        / "checkpoints"
        / "agent_safetybench"
        / defense
        / model.replace("/", "_")
        / run_tag
        / f"{checkpoint_name}.json"
    )
    if checkpoint.exists():
        cached = json.loads(checkpoint.read_text(encoding="utf-8"))
        metadata = cached.get("_agentgate", {})
        if {"discovery_blocks", "capability_failures"} <= metadata.keys():
            return cached

    started = time.perf_counter()
    environments, tool_descriptions = _prepare_environments(case, env_manager)
    all_tools = [{"type": "function", "function": item} for item in tool_descriptions]
    tools = all_tools
    messages: list[dict[str, Any]] = [{"role": "system", "content": prompt}]
    messages.extend(deepcopy(case.get("dialog", [])))
    if "dialog" not in case:
        messages.append({"role": "user", "content": case["instruction"]})
    evaluation = case.get("_evaluation", {})

    runtime = None
    adapter = None
    context = None
    decisions: list[dict[str, Any]] = []
    capability_failures: list[dict[str, str]] = []
    registered_names: set[str] = set()
    if defense == "agentgate" and tool_descriptions:
        audit_path = (
            output_root
            / "raw/agent_safetybench/audit"
            / model.replace("/", "_")
            / f"{checkpoint_name}.jsonl"
        )
        audit_path.unlink(missing_ok=True)
        runtime = build_runtime(
            AgentGateSettings(
                audit_path=audit_path,
                internal_domains={"internal.test", "company.test"},
            )
        )
        adapter = FunctionToolAdapter(runtime)
        authorization_id = None
        if evaluation.get("label") == "negative":
            authorization = await runtime.authorize_task(
                principal="agent-safetybench-user",
                task_id=case_id,
                goal=_trusted_task_goal(case),
                entitlements={
                    "operations": [item.value for item in SecurityOperation],
                    "resources": ["*"],
                    "effects": [item.value for item in EffectType],
                    "destinations": ["*"],
                    "max_records": 100,
                },
                issuer="agent-safetybench-trusted-user-prompt",
            )
            authorization_id = authorization.authorization_id
        context = RuntimeContext(
            principal="agent-safetybench-user",
            session_id=f"agent-safetybench-{case_id}",
            task_id=case_id,
            agent_id=f"{model}-agent",
            authorization_id=authorization_id,
        )
        for description in tool_descriptions:
            name = description["name"]
            if name in registered_names:
                continue
            environment = _find_environment(environments, name)
            if environment is None:
                continue

            async def executor(arguments, env=environment, tool_name=name):
                result = await asyncio.to_thread(
                    _call_environment_tool,
                    env,
                    tool_name,
                    arguments,
                )
                success = not (isinstance(result, dict) and result.get("success") is False)
                return ToolExecutionResult(
                    output=result,
                    success=success,
                    affected_count=1 if success else 0,
                )

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
                    possible_operations=[SecurityOperation.UNKNOWN],
                    resource_type=ResourceType.UNKNOWN,
                    source="conservative_unknown",
                    confidence=0.0,
                    evidence=["semantic_resolution_failed"],
                )
            try:
                await adapter.register(name=name, capability=capability, executor=executor)
                registered_names.add(name)
            except ValueError as exc:
                decisions.append(
                    {
                        "round": 0,
                        "call_id": f"discovery-{case_id}-{name}",
                        "tool_name": name,
                        "operation": "DISCOVERY",
                        "decision": "BLOCK",
                        "rule_ids": ["unsafe_tool_description"],
                        "executed": False,
                        "reason": str(exc),
                    }
                )
        tools = [item for item in all_tools if item["function"]["name"] in registered_names]
    baseline_guard = build_baseline_guard(
        defense,
        tool_descriptions,
        task_goal=_trusted_task_goal(case),
    )

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
            baseline_decision = (
                await baseline_guard.a_before_call(call.function.name, arguments, call.id)
                if baseline_guard is not None
                else None
            )
            executed = False
            if baseline_decision is not None and not baseline_decision.permits_execution:
                result = {
                    "success": False,
                    "message": f"{DEFENSE_LABELS[defense]} BLOCK: {baseline_decision.reason}",
                }
            elif environment is None:
                result: Any = {
                    "success": False,
                    "message": f"Tool {call.function.name} doesn't exist.",
                }
            elif adapter is None or context is None:
                result = await asyncio.to_thread(
                    _call_environment_tool,
                    environment,
                    call.function.name,
                    arguments,
                )
                executed = True
            else:
                outcome = await adapter.invoke(
                    tool_name=call.function.name,
                    arguments=arguments,
                    context=context,
                    call_id=call.id,
                    source_framework="agent-safetybench",
                    source_transport="in_process_executable",
                )
                if (
                    evaluation.get("authorized_sink_control")
                    and outcome.decision.action.value == "REQUIRE_APPROVAL"
                    and outcome.decision.approval_id
                ):
                    _, approval_token = await runtime.approvals.approve(
                        outcome.decision.approval_id
                    )
                    outcome = await adapter.invoke(
                        tool_name=call.function.name,
                        arguments=arguments,
                        context=context,
                        call_id=call.id,
                        approval_token=approval_token,
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
                        "success": outcome.execution.success if outcome.execution else None,
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
                    executed = True
            success = executed and not (isinstance(result, dict) and result.get("success") is False)
            if baseline_guard is not None:
                if executed:
                    baseline_guard.after_call(
                        call.function.name,
                        arguments,
                        call.id,
                        result,
                    )
                decisions.append(
                    {
                        "round": rounds,
                        "call_id": call.id,
                        "tool_name": call.function.name,
                        "operation": "BASELINE_POLICY",
                        "decision": baseline_decision.action,
                        "rule_ids": list(baseline_decision.rule_ids),
                        "executed": executed,
                        "success": success,
                    }
                )
            elif defense == "no_defense":
                decisions.append(
                    {
                        "round": rounds,
                        "call_id": call.id,
                        "tool_name": call.function.name,
                        "operation": "UNMEDIATED",
                        "decision": "ALLOW",
                        "rule_ids": [],
                        "executed": executed,
                        "success": success,
                    }
                )
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

    generated_tool_calls = sum(
        len(message.get("tool_calls", []))
        for message in messages
        if message.get("role") == "assistant"
    )
    sink_tools = set(evaluation.get("sink_tools", []))
    successful_sink = any(
        item.get("tool_name") in sink_tools and item.get("executed") and item.get("success")
        for item in decisions
        if item.get("round", 0) > 0
    )
    benign_tool = evaluation.get("benign_tool")
    benign_tool_success = any(
        item.get("tool_name") == benign_tool and item.get("executed") and item.get("success")
        for item in decisions
        if item.get("round", 0) > 0
    )
    output = {
        **case,
        "output": messages,
        "_agentgate": {
            "benchmark": "Agent-SafetyBench",
            "benchmark_commit": git_revision(benchmark_root),
            "model": model,
            "defense": DEFENSE_LABELS[defense],
            "status": status,
            "error": error,
            "rounds": rounds,
            "tool_calls": generated_tool_calls,
            "blocked_calls": sum(not item["executed"] for item in decisions),
            "discovery_blocks": sum(item["round"] == 0 for item in decisions),
            "applicable_to_agentgate": bool(tool_descriptions),
            "applicability_reason": (
                "At least one structured tool call can be mediated."
                if tool_descriptions
                else "The task exposes no structured tool control point."
            ),
            "structured_tool_call_observed": generated_tool_calls > 0,
            "run_tag": run_tag,
            "decisions": decisions,
            "capability_failures": capability_failures,
            "end_to_end_latency_ms": (time.perf_counter() - started) * 1000,
            "official_shield_label": None,
            "evaluation_label": evaluation.get("label", "positive"),
            "evaluation_case_id": evaluation.get("case_id", str(case["id"])),
            "source_case_id": evaluation.get("source_case_id", case["id"]),
            "sink_tools": sorted(sink_tools),
            "successful_sink_executed": successful_sink,
            "benign_tool": benign_tool,
            "benign_tool_success": benign_tool_success,
            "objective_task_success": (
                benign_tool_success if evaluation.get("label") == "negative" else None
            ),
            "authorized_sink_control": bool(evaluation.get("authorized_sink_control")),
        },
    }
    checkpoint.parent.mkdir(parents=True, exist_ok=True)
    checkpoint.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    return output


def _write_summary(output_root: Path, records: list[dict[str, Any]], run_tag: str) -> None:
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
                "completed": sum(item["status"] != "error" for item in metadata),
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
        / f"agent_safetybench_{defense.lower().replace(' ', '_')}_{run_tag}_execution.csv",
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
    manifest_rows: list[dict[str, Any]] | None = None,
    run_tag: str = "full",
) -> list[dict[str, Any]]:
    benchmark_root = Path(benchmark_root).resolve()
    output_root = Path(output_root)
    cases = json.loads((benchmark_root / "data/released_data.json").read_text(encoding="utf-8"))
    if manifest_rows is not None:
        by_id = {int(case["id"]): case for case in cases}
        selected_cases = []
        for row in manifest_rows:
            if row.get("benchmark") != "Agent-SafetyBench":
                continue
            source_id = int(row["source_case_id"])
            if case_ids is not None and source_id not in case_ids:
                continue
            case = deepcopy(by_id[source_id])
            case["_evaluation"] = deepcopy(row)
            if row["label"] == "negative":
                case["instruction"] = row["control_instruction"]
                case.pop("dialog", None)
            selected_cases.append(case)
        cases = selected_cases
    elif case_ids:
        cases = [case for case in cases if case["id"] in case_ids]
    if limit is not None:
        cases = cases[:limit]
    prompt = _official_prompt(benchmark_root)
    env_manager = _load_env_manager(benchmark_root)
    client = AsyncOpenAI(
        api_key=os.environ["LLM_API"],
        base_url=os.environ["LLM_URL"],
        timeout=float(os.getenv("EVALUATION_LLM_TIMEOUT_SECONDS", "45")),
        max_retries=1,
    )
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
                run_tag=run_tag,
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
        / f"gen_res_{run_tag}.json"
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
    write_jsonl(
        output_root / "normalized" / f"agent_safetybench_{defense}_{run_tag}.jsonl",
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
    _write_summary(output_root, records, run_tag)
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
    parser.add_argument(
        "--defense",
        choices=["agentgate", "no_defense", "agentspec", "invariant"],
        default="agentgate",
    )
    parser.add_argument("--concurrency", type=int, default=16)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--case-id", action="append", type=int, dest="case_ids")
    parser.add_argument(
        "--manifest",
        help="Run Agent-SafetyBench source IDs from a frozen subset manifest.",
    )
    parser.add_argument("--run-tag", default="full")
    args = parser.parse_args()
    case_ids = set(args.case_ids) if args.case_ids else None
    manifest_rows = None
    if args.manifest:
        manifest_rows = [
            json.loads(line)
            for line in Path(args.manifest).read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        manifest_ids = {
            int(row["source_case_id"])
            for row in manifest_rows
            if row["benchmark"] == "Agent-SafetyBench"
        }
        case_ids = manifest_ids if case_ids is None else case_ids & manifest_ids
    records = asyncio.run(
        run_agent_safetybench(
            benchmark_root=args.benchmark_root,
            output_root=args.output_root,
            model=args.model,
            defense=args.defense,
            concurrency=args.concurrency,
            retries=args.retries,
            limit=args.limit,
            case_ids=case_ids,
            manifest_rows=manifest_rows,
            run_tag=args.run_tag,
        )
    )
    print(f"completed {len(records)} Agent-SafetyBench tasks")


if __name__ == "__main__":
    main()
