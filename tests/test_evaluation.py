from __future__ import annotations

from pathlib import Path

import pytest

from agentgate.evaluation import evaluate_dataset
from agentgate.evaluation.adapters.toolsafe import (
    _compute_trajectory_analysis,
    _load_records,
    _sample_complete_interactions,
    _tool_spec_from_env,
    _toolsafe_session_id,
    parse_current_action,
)
from agentgate.evaluation.metrics import MetricRow, compute_metrics


async def test_agentgatebench_full_outperforms_no_guard() -> None:
    dataset = "benchmarks/agentgatebench/cases.jsonl"
    full = await evaluate_dataset(dataset, mode="full")
    no_guard = await evaluate_dataset(dataset, mode="no_guard")
    assert full.metrics["f1"] > no_guard.metrics["f1"]
    assert full.metrics["attack_success_rate"] < no_guard.metrics["attack_success_rate"]
    assert full.metrics["cases"] == 40


def test_metrics_explicitly_report_false_positives_and_false_negatives() -> None:
    rows = [
        MetricRow("tp", "test", True, "DENY", "DENY", 1.0),
        MetricRow("fp", "test", False, "ALLOW", "DENY", 1.0),
        MetricRow("tn", "test", False, "ALLOW", "ALLOW", 1.0),
        MetricRow("fn", "test", True, "DENY", "ALLOW", 1.0),
    ]

    metrics = compute_metrics(rows)

    assert metrics["fp"] == 1
    assert metrics["fn"] == 1
    assert metrics["false_positive_rate"] == 0.5
    assert metrics["false_negative_rate"] == 0.5
    assert metrics["attack_success_rate"] == metrics["false_negative_rate"]


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
    assert analysis["interaction_confusion"] == {
        "tp": 1,
        "fp": 0,
        "tn": 0,
        "fn": 1,
        "false_positive_rate": 0.0,
        "false_negative_rate": 0.5,
    }


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


def test_toolsafe_adapter_preserves_parameter_schema_and_interaction_session() -> None:
    env_info = """lookup: Read a customer record.
  parameters:
    customer_id: {'description': 'Customer identifier', 'type': 'string'}
    limit: {'description': 'Maximum records', 'type': 'integer'}

send: Send a message.
"""
    spec = _tool_spec_from_env("lookup", env_info, {"customer_id": "C1", "limit": 1})
    first = {
        "_agentgate_family": "agentdojo",
        "_agentgate_source": "suite.json",
        "id-interaction": 7,
        "id-segment": 0,
    }
    second = {**first, "id-segment": 1}

    assert spec.description == "Read a customer record."
    assert spec.input_schema["properties"]["customer_id"]["type"] == "string"
    assert spec.input_schema["properties"]["limit"]["type"] == "integer"
    assert _toolsafe_session_id(first, 0) == _toolsafe_session_id(second, 1)
