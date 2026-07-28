from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel, Field, SecretStr


class AgentGateSettings(BaseModel):
    llm_enabled: bool = False
    llm_provider: str = "packy"
    llm_base_url: str = "https://www.packyapi.com/v1"
    llm_api_key: SecretStr | None = None
    llm_model: str = "gpt-5.5"
    llm_timeout_seconds: float = 30.0
    llm_max_retries: int = Field(default=2, ge=0, le=10)
    llm_retry_backoff_seconds: float = Field(default=0.5, ge=0.0)
    llm_max_output_tokens: int = Field(default=4096, ge=64, le=32768)
    llm_batch_size: int = Field(default=20, ge=1, le=100)
    llm_concurrency: int = Field(default=4, ge=1, le=32)
    llm_fail_closed: bool = False
    policy_backend: str = "builtin"
    opa_url: str = "http://127.0.0.1:8181"
    opa_policy_path: str = "agentgate/authorization/decision"
    audit_path: Path = Path(".agentgate/audit.jsonl")
    integrity_block_severity: int = Field(default=8, ge=1, le=10)
    semantic_confidence_threshold: float = Field(default=0.75, ge=0.0, le=1.0)
    personal_record_budget: int = 20
    external_transmission_budget: int = 1
    privileged_operation_budget: int = 2

    @classmethod
    def from_env(cls, env_file: str | Path = ".env") -> AgentGateSettings:
        load_dotenv(env_file, override=False)
        generic_url = os.getenv("AGENTGATE_LLM_BASE_URL")
        generic_key = os.getenv("AGENTGATE_LLM_API_KEY")
        poe_url = os.getenv("POE_API_URL", "https://api.poe.com/v1")
        poe_key = os.getenv("POE_API_KEY")
        sub_url = os.getenv("SUB_URL")
        sub_key = os.getenv("SUB_LLM_API")
        packy_url = os.getenv("PACKY_API_URL", "https://www.packyapi.com/v1")
        packy_key = os.getenv("PACKY_API_KEY_DEFAULT")

        if generic_url and generic_key:
            provider = "custom"
            base_url = generic_url
            api_key = generic_key
        elif poe_key:
            provider = "poe"
            base_url = poe_url
            api_key = poe_key
        elif sub_url and sub_key:
            provider = "sub"
            base_url = sub_url
            api_key = sub_key
        else:
            provider = "packy"
            base_url = packy_url
            api_key = packy_key

        return cls(
            llm_enabled=_as_bool(os.getenv("AGENTGATE_LLM_ENABLED", "false")),
            llm_provider=provider,
            llm_base_url=_normalize_openai_base_url(base_url),
            llm_api_key=SecretStr(api_key) if api_key else None,
            llm_model=os.getenv("LLM_MODEL_DEFAULT", "gpt-5.5"),
            llm_timeout_seconds=float(os.getenv("AGENTGATE_LLM_TIMEOUT", "30")),
            llm_max_retries=int(os.getenv("AGENTGATE_LLM_MAX_RETRIES", "2")),
            llm_retry_backoff_seconds=float(os.getenv("AGENTGATE_LLM_RETRY_BACKOFF", "0.5")),
            llm_max_output_tokens=int(os.getenv("AGENTGATE_LLM_MAX_OUTPUT_TOKENS", "4096")),
            llm_batch_size=int(os.getenv("AGENTGATE_LLM_BATCH_SIZE", "20")),
            llm_concurrency=int(os.getenv("AGENTGATE_LLM_CONCURRENCY", "4")),
            llm_fail_closed=_as_bool(os.getenv("AGENTGATE_LLM_FAIL_CLOSED", "false")),
            policy_backend=os.getenv("AGENTGATE_POLICY_BACKEND", "builtin"),
            opa_url=os.getenv("AGENTGATE_OPA_URL", "http://127.0.0.1:8181").rstrip("/"),
            opa_policy_path=os.getenv(
                "AGENTGATE_OPA_POLICY_PATH", "agentgate/authorization/decision"
            ),
            audit_path=Path(os.getenv("AGENTGATE_AUDIT_PATH", ".agentgate/audit.jsonl")),
            integrity_block_severity=int(os.getenv("AGENTGATE_INTEGRITY_BLOCK_SEVERITY", "8")),
            semantic_confidence_threshold=float(
                os.getenv("AGENTGATE_SEMANTIC_CONFIDENCE_THRESHOLD", "0.75")
            ),
            personal_record_budget=int(os.getenv("AGENTGATE_PERSONAL_RECORD_BUDGET", "20")),
            external_transmission_budget=int(
                os.getenv("AGENTGATE_EXTERNAL_TRANSMISSION_BUDGET", "1")
            ),
            privileged_operation_budget=int(
                os.getenv("AGENTGATE_PRIVILEGED_OPERATION_BUDGET", "2")
            ),
        )


def _as_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _normalize_openai_base_url(value: str) -> str:
    base_url = value.rstrip("/")
    if base_url.endswith("/v1"):
        return base_url
    return f"{base_url}/v1"
