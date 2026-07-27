from __future__ import annotations

from agentgate.config import AgentGateSettings


def test_sub_credentials_are_preferred_and_normalized(monkeypatch, tmp_path) -> None:
    for name in (
        "AGENTGATE_LLM_BASE_URL",
        "AGENTGATE_LLM_API_KEY",
        "PACKY_API_URL",
        "PACKY_API_KEY_DEFAULT",
        "SUB_URL",
        "SUB_LLM_API",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SUB_URL", "https://sub.example.test/")
    monkeypatch.setenv("SUB_LLM_API", "test-only-sub-key")

    settings = AgentGateSettings.from_env(tmp_path / "missing.env")

    assert settings.llm_provider == "sub"
    assert settings.llm_base_url == "https://sub.example.test/v1"
    assert settings.llm_api_key is not None
    assert settings.llm_api_key.get_secret_value() == "test-only-sub-key"
