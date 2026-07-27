from __future__ import annotations

from agentgate.evaluation import evaluate_dataset
from agentgate.evaluation.adapters.toolsafe import parse_current_action


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
