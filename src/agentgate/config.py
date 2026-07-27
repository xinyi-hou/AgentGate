from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel, Field, SecretStr


class AgentGateSettings(BaseModel):
    llm_enabled: bool = False
    llm_base_url: str = "https://www.packyapi.com/v1"
    llm_api_key: SecretStr | None = None
    llm_model: str = "gpt-5.5"
    llm_timeout_seconds: float = 30.0
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
        return cls(
            llm_enabled=_as_bool(os.getenv("AGENTGATE_LLM_ENABLED", "false")),
            llm_base_url=os.getenv("PACKY_API_URL", "https://www.packyapi.com/v1").rstrip("/"),
            llm_api_key=(
                SecretStr(value) if (value := os.getenv("PACKY_API_KEY_DEFAULT")) else None
            ),
            llm_model=os.getenv("LLM_MODEL_DEFAULT", "gpt-5.5"),
            llm_timeout_seconds=float(os.getenv("AGENTGATE_LLM_TIMEOUT", "30")),
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
