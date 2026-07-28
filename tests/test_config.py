from __future__ import annotations

from agentgate.config import AgentGateSettings


def test_sub_credentials_are_preferred_and_normalized(monkeypatch, tmp_path) -> None:
    for name in (
        "AGENTGATE_LLM_BASE_URL",
        "AGENTGATE_LLM_API_KEY",
        "POE_API_URL",
        "POE_API_KEY",
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


def test_poe_credentials_are_supported(monkeypatch, tmp_path) -> None:
    for name in (
        "AGENTGATE_LLM_BASE_URL",
        "AGENTGATE_LLM_API_KEY",
        "POE_API_URL",
        "POE_API_KEY",
        "SUB_URL",
        "SUB_LLM_API",
        "PACKY_API_URL",
        "PACKY_API_KEY_DEFAULT",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("POE_API_URL", "https://api.poe.example/v1/")
    monkeypatch.setenv("POE_API_KEY", "test-only-poe-key")

    settings = AgentGateSettings.from_env(tmp_path / "missing.env")

    assert settings.llm_provider == "poe"
    assert settings.llm_base_url == "https://api.poe.example/v1"
    assert settings.llm_api_key is not None
    assert settings.llm_api_key.get_secret_value() == "test-only-poe-key"


def test_model_catalog_selects_family_specific_credentials(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PACKY_API_URL", "https://packy.example.test")
    monkeypatch.setenv("PACKY_API_KEY_KIMI", "test-only-kimi-key")
    monkeypatch.setenv("LLM_MODEL_KIMI_1", "kimi-small")

    settings = AgentGateSettings.for_model(
        "LLM_MODEL_KIMI_1",
        tmp_path / "missing.env",
    )

    assert settings.llm_enabled
    assert settings.llm_provider == "packy-kimi"
    assert settings.llm_base_url == "https://packy.example.test/v1"
    assert settings.llm_model == "kimi-small"
    assert settings.llm_api_key is not None
    assert settings.llm_api_key.get_secret_value() == "test-only-kimi-key"


def test_gpt_catalog_prefers_sub_endpoint_over_poe(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("LLM_MODEL_GPT", "gpt-test")
    monkeypatch.setenv("SUB_URL", "https://sub.example.test")
    monkeypatch.setenv("SUB_LLM_API", "test-only-sub-key")
    monkeypatch.setenv("POE_API_URL", "https://poe.example.test")
    monkeypatch.setenv("POE_API_KEY", "test-only-poe-key")

    settings = AgentGateSettings.for_model("gpt-test", tmp_path / "missing.env")

    assert settings.llm_provider == "sub"
    assert settings.llm_base_url == "https://sub.example.test/v1"
    assert settings.llm_api_key is not None
    assert settings.llm_api_key.get_secret_value() == "test-only-sub-key"
