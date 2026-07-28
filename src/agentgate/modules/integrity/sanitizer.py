from __future__ import annotations

from collections.abc import Iterable

from agentgate.models import IntegrityFinding
from agentgate.modules.integrity.detector import PATTERNS


def sanitize_content(
    content: str,
    findings: Iterable[IntegrityFinding] = (),
) -> str:
    materialized = list(findings)
    blocking_risks = sorted(
        {finding.risk_type for finding in materialized if finding.severity >= 8}
    )
    if blocking_risks:
        risks = ",".join(blocking_risks)
        return f"[AGENTGATE_ISOLATED:{risks}]"

    sanitized = content
    for risk_type, _, pattern in PATTERNS:
        sanitized = pattern.sub(f"[AGENTGATE_ISOLATED:{risk_type}]", sanitized)
    semantic_risks = sorted(
        {finding.risk_type for finding in materialized if finding.source.startswith("llm")}
    )
    if semantic_risks and sanitized == content:
        risks = ",".join(semantic_risks)
        return f"[AGENTGATE_ISOLATED:{risks}]"
    return sanitized
