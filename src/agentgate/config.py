from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from pydantic import BaseModel, Field


class AgentGateSettings(BaseModel):
    audit_backend: Literal["jsonl", "sqlite"] = "jsonl"
    audit_path: Path = Path(".agentgate/security-audit.jsonl")
    unsafe_debug_audit_payloads: bool = False

    policy_path: Path | None = None
    session_ttl_seconds: int = Field(default=3600, ge=60)
    history_limit: int = Field(default=200, ge=1)
    history_ttl_seconds: int = Field(default=3600, ge=60)
    approval_ttl_seconds: int = Field(default=300, ge=10)

    redis_url: str | None = None
    internal_domains: set[str] = Field(default_factory=set)
    trusted_external_domains: set[str] = Field(default_factory=set)

    @classmethod
    def from_env(cls, env_file: str | Path = ".env") -> AgentGateSettings:
        load_dotenv(env_file, override=False)
        policy_path = os.getenv("AGENTGATE_POLICY_PATH")
        return cls(
            audit_backend=os.getenv("AGENTGATE_AUDIT_BACKEND", "jsonl").lower(),
            audit_path=Path(os.getenv("AGENTGATE_AUDIT_PATH", ".agentgate/security-audit.jsonl")),
            unsafe_debug_audit_payloads=_as_bool(
                os.getenv("AGENTGATE_UNSAFE_DEBUG_AUDIT_PAYLOADS", "false")
            ),
            policy_path=Path(policy_path) if policy_path else None,
            session_ttl_seconds=int(os.getenv("AGENTGATE_SESSION_TTL_SECONDS", "3600")),
            history_limit=int(os.getenv("AGENTGATE_HISTORY_LIMIT", "200")),
            history_ttl_seconds=int(os.getenv("AGENTGATE_HISTORY_TTL_SECONDS", "3600")),
            approval_ttl_seconds=int(os.getenv("AGENTGATE_APPROVAL_TTL_SECONDS", "300")),
            redis_url=os.getenv("AGENTGATE_REDIS_URL") or None,
            internal_domains=_csv_set(os.getenv("AGENTGATE_INTERNAL_DOMAINS", "")),
            trusted_external_domains=_csv_set(os.getenv("AGENTGATE_TRUSTED_EXTERNAL_DOMAINS", "")),
        )


def _as_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _csv_set(value: str) -> set[str]:
    return {item.strip().lower() for item in value.split(",") if item.strip()}
