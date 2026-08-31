from __future__ import annotations

import asyncio
from pathlib import Path

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
