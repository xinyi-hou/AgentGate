from __future__ import annotations

from pathlib import Path

import pytest

from agentgate.evaluation import evaluate_dataset
from agentgate.evaluation.adapters.toolsafe import (
    _compute_trajectory_analysis,
    _load_records,
    _sample_complete_interactions,
    parse_current_action,
)
from agentgate.evaluation.metrics import MetricRow


async def test_agentgatebench_full_outperforms_no_guard() -> None:
    dataset = "benchmarks/agentgatebench/cases.jsonl"
    full = await evaluate_dataset(dataset, mode="full")
    no_guard = await evaluate_dataset(dataset, mode="no_guard")
    assert full.metrics["f1"] > no_guard.metrics["f1"]
    assert full.metrics["attack_success_rate"] < no_guard.metrics["attack_success_rate"]
    assert full.metrics["cases"] == 40


def test_toolsafe_parser_ignores_action_text_inside_arguments() -> None:
    text = """(1) Thought: Send a transcript.
(2) Action: send_email
(3) Action Input: {
  "recipients": ["reviewer@example.com"],
  "body": "Prior trace: (2) Action: read_file\\n(3) Action Input: {}"
}
"""
    action, arguments = parse_current_action(text)
    assert action == "send_email"
    assert arguments["recipients"] == ["reviewer@example.com"]


def test_toolsafe_loader_rejects_missing_or_empty_source(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="does not exist"):
        _load_records(tmp_path / "missing.json")
    with pytest.raises(ValueError, match="contains no JSON records"):
        _load_records(tmp_path)


def test_trajectory_analysis_excludes_steps_after_first_denial() -> None:
    rows = [
        MetricRow("one", "asb", False, "ALLOW", "ALLOW", 1.0),
        MetricRow("one", "asb", True, "DENY", "DENY", 1.0),
        MetricRow("one", "asb", False, "ALLOW", "DENY", 1.0),
        MetricRow("two", "asb", True, "DENY", "ALLOW", 1.0),
    ]
    details = [
        {"interaction_id": 1, "family": "asb", "source": "dpi", "index": 0},
        {"interaction_id": 1, "family": "asb", "source": "dpi", "index": 1},
        {"interaction_id": 1, "family": "asb", "source": "dpi", "index": 2},
        {"interaction_id": 2, "family": "asb", "source": "dpi", "index": 3},
    ]

    analysis = _compute_trajectory_analysis(rows, details)

    assert analysis["reachable_steps"] == 3
    assert analysis["unreachable_steps"] == 1
    assert analysis["attack_success_rate"] == 0.5
    assert analysis["reachable_metrics"]["benign_completion_rate"] == 1.0


def test_toolsafe_sampling_is_deterministic_and_keeps_interactions_complete() -> None:
    records = [
        {
            "_agentgate_source": "dpi",
            "id-interaction": interaction,
            "id-segment": segment,
        }
        for interaction in range(10)
        for segment in range(3)
    ]

    first = _sample_complete_interactions(records, requested_records=10, seed=7)
    second = _sample_complete_interactions(records, requested_records=10, seed=7)

    assert first == second
    selected = {record["id-interaction"] for record in first}
    assert all(
        sum(record["id-interaction"] == interaction for record in first) == 3
        for interaction in selected
    )
