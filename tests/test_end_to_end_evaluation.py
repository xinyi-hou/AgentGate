from __future__ import annotations

import asyncio
from pathlib import Path

from evaluation.recording import write_jsonl
from evaluation.runners.build_public_tables import build_public_table
from evaluation.statefulbench.cases import stateful_cases
from evaluation.statefulbench.runner import run_statefulbench


def _cases(*case_ids: str):
    selected = set(case_ids)
    return [case for case in stateful_cases() if case.case_id in selected]


def test_statefulbench_v2_has_balanced_unique_200_task_matrix() -> None:
    cases = stateful_cases()

    assert len(cases) == 200
    assert len({case.case_id for case in cases}) == 200
    assert len({case.risk_type for case in cases}) == 20
    assert sum(case.is_attack for case in cases) == 100
    assert sum(not case.is_attack for case in cases) == 100
    by_id = {case.case_id: case for case in cases}
    assert all(by_id[case.paired_case_id].paired_case_id == case.case_id for case in cases)


def test_full_runtime_blocks_harmful_sink_before_execution(tmp_path: Path) -> None:
    tasks, calls = asyncio.run(
        run_statefulbench(
            modes=["full"],
            output_root=tmp_path,
            cases=_cases("direct_attack", "direct_benign"),
        )
    )
    attack = next(item for item in tasks if item.case_id == "direct_attack")
    benign = next(item for item in tasks if item.case_id == "direct_benign")

    assert attack.blocked
    assert attack.attack_prevented_before_side_effect
    assert not attack.harmful_side_effect_occurred
    assert attack.block_phase == "request"
    assert benign.task_success
    assert not benign.blocked
    assert any(not call.executed for call in calls if call.case_id == "direct_attack")


def test_no_defense_executes_the_isolated_harmful_side_effect(tmp_path: Path) -> None:
    tasks, _ = asyncio.run(
        run_statefulbench(
            modes=["no_defense"],
            output_root=tmp_path,
            cases=_cases("direct_attack"),
        )
    )

    assert tasks[0].attack_success
    assert tasks[0].harmful_side_effect_occurred
    assert not tasks[0].blocked


def test_provenance_ablation_removes_data_graph_entities(tmp_path: Path) -> None:
    tasks, _ = asyncio.run(
        run_statefulbench(
            modes=["atg_no_provenance"],
            output_root=tmp_path,
            cases=_cases("transform_attack"),
        )
    )

    snapshot = tasks[0].atg
    assert snapshot.data_object_nodes == 0
    assert snapshot.produces_edges == 0
    assert snapshot.consumes_edges == 0
    assert snapshot.derives_from_edges == 0


def test_public_table_separates_solvable_and_applicable_denominators(
    tmp_path: Path,
) -> None:
    normalized = tmp_path / "normalized"
    write_jsonl(
        normalized / "agentdojo_agentgate_full.jsonl",
        [
            {
                "status": "completed",
                "defense": "AgentGate",
                "injection_task_solvable": True,
                "attack_success": False,
                "utility": True,
                "blocked_calls": 1,
            },
            {
                "status": "completed",
                "defense": "AgentGate",
                "injection_task_solvable": False,
                "attack_success": False,
                "utility": False,
                "blocked_calls": 0,
            },
        ],
    )
    write_jsonl(
        normalized / "agent_safetybench_agentgate.jsonl",
        [
            {
                "id": 1,
                "status": "completed",
                "applicable_to_agentgate": True,
                "blocked_calls": 1,
            },
            {
                "id": 2,
                "status": "completed",
                "applicable_to_agentgate": False,
                "blocked_calls": 0,
            },
        ],
    )
    write_jsonl(
        normalized / "agent_safetybench_agentgate_api_scores.jsonl",
        [
            {"id": 1, "status": "completed", "label": "safe", "defense": "AgentGate"},
            {"id": 2, "status": "completed", "label": "unsafe", "defense": "AgentGate"},
        ],
    )

    rows = build_public_table(tmp_path)

    dojo = next(item for item in rows if item["benchmark"] == "AgentDojo v1.2")
    safety = next(item for item in rows if item["benchmark"] == "Agent-SafetyBench")
    assert dojo["safety_denominator"] == 1
    assert dojo["utility_denominator"] == 2
    assert safety["safety_denominator"] == 2
    assert safety["applicable_safety_denominator"] == 1
    assert safety["unsafe_or_attack_success_rate"] == 0.5
    assert safety["applicable_unsafe_or_attack_success_rate"] == 0.0
    table = (tmp_path / "tables" / "rq1_public_end_to_end.csv").read_text(encoding="utf-8")
    assert "applicable_safety_denominator" in table
