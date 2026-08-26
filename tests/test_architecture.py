from __future__ import annotations

from pathlib import Path

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
