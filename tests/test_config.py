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
        )
    )

    assert runtime.state_manager.history_ttl.total_seconds() == 3600
