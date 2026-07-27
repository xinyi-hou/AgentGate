from __future__ import annotations

from agentgate.modules.integrity.detector import PATTERNS


def sanitize_content(content: str) -> str:
    sanitized = content
    for risk_type, _, pattern in PATTERNS:
        sanitized = pattern.sub(f"[AGENTGATE_ISOLATED:{risk_type}]", sanitized)
    return sanitized
