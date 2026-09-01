from __future__ import annotations

from agentgate.config import AgentGateSettings
from agentgate.runtime import build_runtime


def test_settings_parse_runtime_state_audit_and_domain_configuration(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("AGENTGATE_AUDIT_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("AGENTGATE_AUDIT_BACKEND", "sqlite")
    monkeypatch.setenv("AGENTGATE_SESSION_TTL_SECONDS", "7200")
    monkeypatch.setenv("AGENTGATE_INTERNAL_DOMAINS", "corp.test, services.internal")
    monkeypatch.setenv("AGENTGATE_TRUSTED_EXTERNAL_DOMAINS", "partner.test")
    monkeypatch.setenv("AGENTGATE_UNSAFE_DEBUG_AUDIT_PAYLOADS", "true")

    settings = AgentGateSettings.from_env(tmp_path / "missing.env")

    assert settings.audit_path == tmp_path / "audit.jsonl"
    assert settings.audit_backend == "sqlite"
    assert settings.session_ttl_seconds == 7200
    assert settings.internal_domains == {"corp.test", "services.internal"}
    assert settings.trusted_external_domains == {"partner.test"}
    assert settings.unsafe_debug_audit_payloads is True


def test_runtime_history_covers_the_largest_detection_window(tmp_path) -> None:
    runtime = build_runtime(
        AgentGateSettings(
            audit_path=tmp_path / "audit.jsonl",
            history_ttl_seconds=60,
            llm_enabled=False,
        )
    )

    assert runtime.state_manager.history_ttl.total_seconds() == 3600


def test_llm_is_enabled_by_default_from_compatible_environment(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("LLM_URL", "https://gateway.test")
    monkeypatch.setenv("LLM_API", "test-key")
    monkeypatch.delenv("LLM_DEFAULT_MODEL", raising=False)

    settings = AgentGateSettings.from_env(tmp_path / "missing.env")
    runtime = build_runtime(settings)

    assert settings.llm_enabled is True
    assert runtime.llm_completion is not None
    assert runtime.llm_model == "DeepSeek-V4-Pro-0813"
    assert runtime.graph_builder.dependency_resolver is not None
    assert runtime.graph_detector.resolver is not None
    assert runtime.capability_inferer.semantic_resolver is not None


def test_llm_can_be_explicitly_disabled(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("AGENTGATE_LLM_ENABLED", "false")
    monkeypatch.delenv("LLM_URL", raising=False)
    monkeypatch.delenv("LLM_API", raising=False)

    runtime = build_runtime(AgentGateSettings.from_env(tmp_path / "missing.env"))

    assert runtime.llm_completion is None
    assert runtime.llm_model is None


def test_llm_missing_configuration_falls_back_unless_required(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("AGENTGATE_LLM_ENABLED", "true")
    monkeypatch.delenv("LLM_URL", raising=False)
    monkeypatch.delenv("LLM_API", raising=False)

    settings = AgentGateSettings.from_env(tmp_path / "missing.env")

    assert build_runtime(settings).llm_completion is None

    settings.llm_required = True
    try:
        build_runtime(settings)
    except RuntimeError as exc:
        assert "LLM is required" in str(exc)
    else:
        raise AssertionError("required LLM configuration must fail closed at startup")
