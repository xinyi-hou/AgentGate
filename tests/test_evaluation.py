from __future__ import annotations

from agentgate.evaluation.metrics import MetricRow, compute_metrics
from agentgate.evaluation.toolsafe import parse_current_action
from agentgate.evaluation.trajectory import evaluate_trajectory


def test_metrics_use_unsafe_as_positive_class() -> None:
    metrics = compute_metrics(
        [
            MetricRow("tp", "test", True, True, 1.0),
            MetricRow("fn", "test", True, False, 2.0),
            MetricRow("tn", "test", False, False, 3.0),
            MetricRow("fp", "test", False, True, 4.0),
        ]
    )
    assert metrics["tp"] == metrics["fp"] == metrics["tn"] == metrics["fn"] == 1
    assert metrics["false_positive_rate"] == 0.5
    assert metrics["false_negative_rate"] == 0.5


def test_toolsafe_action_parser_accepts_json_and_python_literals() -> None:
    json_action = '(2) Action: read_record\n(3) Action Input: {"id": "R1"}'
    literal_action = "(2) Action: read_record\n(3) Action Input: {'id': 'R2'}"
    assert parse_current_action(json_action) == ("read_record", {"id": "R1"})
    assert parse_current_action(literal_action) == ("read_record", {"id": "R2"})


async def test_trajectory_replay_distinguishes_stateful_and_stateless_detection() -> None:
    stateful = await evaluate_trajectory("agentgate")
    stateless = await evaluate_trajectory("stateless")
    assert stateful["metrics"]["tp"] == 4
    assert stateful["metrics"]["fp"] == 0
    assert stateless["metrics"]["fn"] == 4
