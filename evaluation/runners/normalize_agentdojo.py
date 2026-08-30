from __future__ import annotations

import argparse
import json
from pathlib import Path
from statistics import mean
from typing import Any

from evaluation.recording import git_revision, read_jsonl, stable_hash, write_jsonl
from evaluation.schema import ArtifactPaths, CallRunRecord, TaskRunRecord


def _tool_calls(messages: list[dict[str, Any]]) -> int:
    return sum(
        len(message.get("tool_calls") or [])
        for message in messages
        if message.get("role") == "assistant"
    )


def _native_records(root: Path, defense: str, directory: str) -> list[TaskRunRecord]:
    base = root / "raw" / "agentdojo" / directory
    records = []
    for path in sorted(base.glob("*/workspace/user_task_*/tool_knowledge/injection_task_0.json")):
        payload = __import__("json").loads(path.read_text(encoding="utf-8"))
        calls = _tool_calls(payload.get("messages", []))
        records.append(
            TaskRunRecord(
                experiment_id="agentdojo-"
                + stable_hash({"defense": defense, "path": str(path)})[:16],
                benchmark="AgentDojo",
                benchmark_commit=git_revision("benchmarks/e2e/agentdojo"),
                case_id=f"workspace:{payload['user_task_id']}:injection_task_0",
                attack_type="tool_knowledge",
                is_attack=True,
                multi_step=True,
                single_server=True,
                defense=defense,
                defense_version="agentdojo-0.1.35" if defense != "AgentGate" else "0.6.0",
                defense_commit=(
                    git_revision("benchmarks/e2e/agentdojo")
                    if defense != "AgentGate"
                    else git_revision()
                ),
                defense_config_hash=stable_hash(
                    {"defense": defense, "model": "DeepSeek-V4-Pro-0813"}
                ),
                agent_model="DeepSeek-V4-Pro-0813",
                task_success=bool(payload["utility"]),
                attack_success=bool(payload["security"]),
                harmful_side_effect_occurred=bool(payload["security"]),
                attack_prevented_before_side_effect=False,
                benign_degraded=not bool(payload["utility"]),
                blocked=defense == "AgentDojo Tool Filter" and not bool(payload["utility"]),
                block_phase="discovery" if defense == "AgentDojo Tool Filter" else "none",
                decision="FILTER" if defense == "AgentDojo Tool Filter" else "ALLOW",
                tool_calls=calls,
                turns=len(payload.get("messages", [])),
                trajectory_length=calls,
                tool_call_successes=calls,
                end_to_end_latency_ms=float(payload.get("duration", 0)) * 1000,
                artifacts=ArtifactPaths(trace_path=str(path)),
                notes=[
                    "AgentDojo security=true means the injection goal was achieved.",
                    "This record is a real AgentDojo executable-environment run.",
                ],
            )
        )
    return records


def _agentgate_records(root: Path) -> list[TaskRunRecord]:
    source = root / "normalized" / "agentdojo_agentgate.jsonl"
    if not source.exists():
        return []
    output = []
    for row in read_jsonl(source):
        path = (
            root
            / "raw"
            / "agentdojo"
            / "agentgate"
            / "openai-compatible-agentgate"
            / row["suite"]
            / row["user_task"]
            / "tool_knowledge"
            / f"{row['injection_task']}.json"
        )
        payload = __import__("json").loads(path.read_text(encoding="utf-8"))
        calls_path = (
            root
            / "raw"
            / "agentdojo"
            / f"agentgate_calls_{row['suite']}_{row['user_task']}_{row['injection_task']}.jsonl"
        )
        if calls_path.exists():
            calls = [
                item for item in read_jsonl(calls_path) if item["user_task_id"] == row["user_task"]
            ]
        else:
            calls_path = root / "raw" / "agentdojo" / "agentgate_calls.jsonl"
            calls = [
                item for item in read_jsonl(calls_path) if item["user_task_id"] == row["user_task"]
            ]
        blocked = any(not item["executed"] for item in calls)
        output.append(
            TaskRunRecord(
                experiment_id="agentdojo-" + stable_hash(row)[:16],
                benchmark="AgentDojo",
                benchmark_commit=row["benchmark_commit"],
                case_id=f"{row['suite']}:{row['user_task']}:{row['injection_task']}",
                attack_type=row["attack"],
                is_attack=True,
                multi_step=True,
                single_server=True,
                defense="AgentGate",
                defense_version="0.6.0",
                defense_commit=git_revision(),
                defense_config_hash=stable_hash(
                    {"defense": "AgentGate", "model": row["agent_model"]}
                ),
                agent_model=row["agent_model"],
                task_success=bool(row["utility"]),
                attack_success=bool(row["attack_success"]),
                harmful_side_effect_occurred=bool(row["attack_success"]),
                attack_prevented_before_side_effect=blocked and not bool(row["attack_success"]),
                blocked=blocked,
                block_phase="request" if blocked else "none",
                decision="BLOCK" if blocked else "ALLOW",
                matched_rules=sorted({rule for call in calls for rule in call["rule_ids"]}),
                tool_calls=len(calls),
                turns=len(payload.get("messages", [])),
                trajectory_length=len(calls),
                tool_call_successes=sum(item["success"] is True for item in calls),
                end_to_end_latency_ms=float(payload.get("duration", 0)) * 1000,
                artifacts=ArtifactPaths(
                    trace_path=str(path),
                    decision_log_path=str(calls_path),
                ),
                notes=[
                    "AgentGate replaces AgentDojo ToolsExecutor; the executable environment "
                    "and benchmark scorer are unchanged.",
                    "A blocked standalone injection precheck is not attributed to the "
                    "combined attack task.",
                ],
            )
        )
    return output


def normalize(output_root: str | Path = "evaluation/results") -> list[TaskRunRecord]:
    root = Path(output_root)
    records = [
        *_native_records(root, "No Defense", "no_defense_attack"),
        *_native_records(root, "AgentDojo Tool Filter", "tool_filter_attack"),
        *_agentgate_records(root),
    ]
    write_jsonl(root / "normalized" / "agentdojo_tasks.jsonl", records)
    write_jsonl(
        root / "normalized" / "agentdojo_calls.jsonl",
        _normalized_calls(root, records),
    )
    groups: dict[str, list[TaskRunRecord]] = {}
    for record in records:
        groups.setdefault(record.defense, []).append(record)
    summary = [
        {
            "benchmark": "AgentDojo",
            "defense": defense,
            "tasks": len(items),
            "asr": mean(item.attack_success for item in items),
            "bcr": mean(item.task_success for item in items),
            "false_block_rate": mean(not item.task_success for item in items),
            "harmful_side_effect_rate": mean(item.harmful_side_effect_occurred for item in items),
            "late_detection_rate": mean(item.late_detection for item in items),
            "mean_end_to_end_latency_ms": mean(item.end_to_end_latency_ms for item in items),
        }
        for defense, items in sorted(groups.items())
    ]
    write_jsonl(root / "normalized" / "agentdojo_summary.jsonl", summary)
    return records


def _normalized_calls(root: Path, tasks: list[TaskRunRecord]) -> list[CallRunRecord]:
    audit_events: dict[str, dict[str, Any]] = {}
    audit_root = root / "raw" / "agentdojo" / "agentgate-audit"
    for path in audit_root.glob("*.jsonl"):
        for row in read_jsonl(path):
            if row.get("event_type") == "CALL_REQUEST":
                event = row.get("payload", {}).get("event", {})
                audit_events[event.get("call_id", "")] = event

    records: list[CallRunRecord] = []
    for task in tasks:
        if task.defense == "AgentGate":
            calls_path = Path(task.artifacts.decision_log_path)
            if not calls_path.exists():
                calls_path = root / "raw" / "agentdojo" / "agentgate_calls.jsonl"
            calls = read_jsonl(calls_path)
            user_task = task.case_id.split(":")[1]
            calls = [item for item in calls if item.get("user_task_id") == user_task]
            for index, call in enumerate(calls, 1):
                event = audit_events.get(call["call_id"], {})
                records.append(
                    CallRunRecord(
                        experiment_id=task.experiment_id,
                        benchmark=task.benchmark,
                        case_id=task.case_id,
                        call_index=index,
                        call_id=call["call_id"],
                        tool_name=call["tool_name"],
                        operation=event.get("operation", "UNKNOWN"),
                        arguments_digest=event.get("arguments_digest", "unavailable"),
                        decision=call["decision"],
                        rule_ids=call["rule_ids"],
                        executed=call["executed"],
                        success=call["success"],
                    )
                )
            continue

        payload = json.loads(Path(task.artifacts.trace_path).read_text(encoding="utf-8"))
        index = 0
        for message in payload.get("messages", []):
            if message.get("role") != "assistant":
                continue
            for call in message.get("tool_calls") or []:
                index += 1
                records.append(
                    CallRunRecord(
                        experiment_id=task.experiment_id,
                        benchmark=task.benchmark,
                        case_id=task.case_id,
                        call_index=index,
                        call_id=call["id"],
                        tool_name=call["function"],
                        operation="UNKNOWN",
                        arguments_digest=stable_hash(call.get("args", {})),
                        decision="FILTER" if task.defense == "AgentDojo Tool Filter" else "ALLOW",
                        executed=task.defense != "AgentDojo Tool Filter",
                        success=task.defense != "AgentDojo Tool Filter",
                    )
                )
    return records


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize executable AgentDojo runs")
    parser.add_argument("--output-root", default="evaluation/results")
    args = parser.parse_args()
    normalize(args.output_root)


if __name__ == "__main__":
    main()
