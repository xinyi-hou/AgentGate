from __future__ import annotations

import json
from pathlib import Path

from agentgate.evaluation.adapters.external_guards import (
    GuardPrediction,
    _parse_qwen3guard,
    evaluate_external_guard,
)


class _FakeGuard:
    name = "fake"
    model_id = "fake/model"
    input_scope = "test"

    def render(self, record: dict) -> str:
        return str(record.get("current_action", ""))

    def predict_many(self, texts: list[str], batch_size: int) -> list[GuardPrediction]:
        return [GuardPrediction(unsafe="block" in text) for text in texts]


def test_external_guard_uses_common_step_and_trajectory_metrics(tmp_path: Path) -> None:
    records = [
        {
            "id-interaction": "attack",
            "id-segment": "1",
            "instruction": "read",
            "history": "",
            "current_action": "allow",
            "env_info": "",
            "score": 0,
        },
        {
            "id-interaction": "attack",
            "id-segment": "2",
            "instruction": "read",
            "history": "",
            "current_action": "block",
            "env_info": "",
            "score": 1,
        },
        {
            "id-interaction": "benign",
            "id-segment": "1",
            "instruction": "read",
            "history": "",
            "current_action": "allow",
            "env_info": "",
            "score": 0,
        },
    ]
    source = tmp_path / "agentdojo-traj"
    source.mkdir()
    (source / "workspace.json").write_text(json.dumps(records), encoding="utf-8")

    report = evaluate_external_guard(source, _FakeGuard(), batch_size=2)

    assert report.metrics["tp"] == 1
    assert report.metrics["tn"] == 2
    assert report.trajectory_metrics["interaction_attack_success_rate"] == 0
    assert report.trajectory_metrics["benign_trajectory_completion_rate"] == 1


def test_qwen3guard_parser_is_strict_and_fails_closed() -> None:
    assert not _parse_qwen3guard("Safety: Safe\nCategories: None").unsafe
    assert _parse_qwen3guard("Safety: Controversial\nCategories: PII").unsafe
    invalid = _parse_qwen3guard("I cannot decide")
    assert invalid.unsafe
    assert invalid.parse_error
