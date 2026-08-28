from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from agentgate.capabilities import (
    CapabilityEvaluation,
    CapabilityGold,
    CapabilityInferer,
    ToolCapability,
    evaluate_capability,
)
from agentgate.events import SecurityOperation


async def test_capability_gold_set_reports_field_level_accuracy() -> None:
    path = Path(__file__).parent / "capabilities" / "gold" / "tools.yaml"
    records = yaml.safe_load(path.read_text(encoding="utf-8"))
    evaluations: list[CapabilityEvaluation] = []
    for record in records:
        capability = await CapabilityInferer().infer(
            name=record["tool_name"],
            description=record["description"],
            input_schema=record["input_schema"],
            output_schema=record["output_schema"],
        )
        evaluations.append(
            evaluate_capability(
                capability,
                CapabilityGold(tool_name=record["tool_name"], **record["expected"]),
            )
        )

    assert all(item.accuracy == 1.0 for item in evaluations)


def test_multi_operation_capability_without_selector_fails_closed() -> None:
    with pytest.raises(ValueError, match="multi-operation"):
        ToolCapability(
            tool_name="filesystem",
            possible_operations=[SecurityOperation.READ, SecurityOperation.DELETE],
        )
