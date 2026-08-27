from __future__ import annotations

from pathlib import Path

from agentgate.policy import DecisionAction

PACKAGE = Path(__file__).parents[1] / "src" / "agentgate"


def source_text(package: str) -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in (PACKAGE / package).glob("*.py"))


def test_event_and_state_modules_do_not_depend_on_decision_modules() -> None:
    forbidden = ("agentgate.detection", "agentgate.enforcement", "agentgate.policy")
    for package in ("events", "state"):
        text = source_text(package)
        assert all(module not in text for module in forbidden)


def test_detection_depends_on_fact_models_but_not_state_mutators() -> None:
    text = source_text("detection")
    assert "agentgate.state.models" in text
    assert "agentgate.state.manager" not in text
    assert "agentgate.state.memory_store" not in text
    assert "agentgate.state.redis_store" not in text


def test_framework_adapters_delegate_to_the_unified_runtime() -> None:
    text = source_text("adapters")
    assert "AgentGateRuntime" in text
    assert "DetectionEngine" not in text
    assert "StateManager" not in text


def test_runtime_declares_the_reference_monitor_control_point() -> None:
    text = (PACKAGE / "runtime" / "gateway.py").read_text(encoding="utf-8")
    assert "Reference monitor" in text
    assert "ToolCallSecurityEventAbstraction" in text
    assert "StatefulRiskControl" in text
    assert "async def evaluate" in text
    assert "async def execute" in text


def test_runtime_control_vocabulary_matches_methodology() -> None:
    assert list(DecisionAction) == [
        DecisionAction.ALLOW,
        DecisionAction.AUDIT,
        DecisionAction.RESTRICT,
        DecisionAction.REQUIRE_APPROVAL,
        DecisionAction.BLOCK,
    ]


def test_sequence_detection_uses_incremental_state_not_history_replay() -> None:
    text = (PACKAGE / "detection" / "sequence_engine.py").read_text(encoding="utf-8")
    assert "state.sequence_progress" in text
    assert "state.recent_sensitive_events" not in text
