from __future__ import annotations

import hashlib
import re
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from agentgate.policy.models import Severity


class ContentRiskType(StrEnum):
    INSTRUCTION_OVERRIDE = "INSTRUCTION_OVERRIDE"
    SECRET_EXFILTRATION = "SECRET_EXFILTRATION"
    TOOL_CALL_INDUCEMENT = "TOOL_CALL_INDUCEMENT"
    CONCEALMENT = "CONCEALMENT"


class ContentMode(StrEnum):
    OBSERVE = "observe"
    SANITIZE = "sanitize"


class ContentFinding(BaseModel):
    risk_type: ContentRiskType
    severity: Severity
    evidence: str
    path: str = "$"
    source: str = "deterministic_pattern"


class ContentAnalysis(BaseModel):
    findings: list[ContentFinding] = Field(default_factory=list)
    sanitized: Any = None

    @property
    def blocked(self) -> bool:
        return any(item.severity in {Severity.HIGH, Severity.CRITICAL} for item in self.findings)


_PATTERNS: tuple[tuple[ContentRiskType, Severity, re.Pattern[str]], ...] = (
    (
        ContentRiskType.INSTRUCTION_OVERRIDE,
        Severity.CRITICAL,
        re.compile(
            r"(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|system|developer)"
            r"\s+(?:instructions?|rules?|prompts?)|"
            r"(?:system|developer)\s+(?:message|instruction)\s*:",
            re.IGNORECASE,
        ),
    ),
    (
        ContentRiskType.SECRET_EXFILTRATION,
        Severity.CRITICAL,
        re.compile(
            r"(?:send|upload|post|email|exfiltrate|share)\b.{0,100}\b"
            r"(?:password|credential|api[ _-]?key|token|secret|private[ _-]?key)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        ContentRiskType.CONCEALMENT,
        Severity.HIGH,
        re.compile(
            r"(?:do not|don't|never)\s+(?:tell|inform|show|mention|reveal)\s+(?:the\s+)?user|"
            r"(?:hide|conceal)\s+(?:this|these|the action)",
            re.IGNORECASE,
        ),
    ),
    (
        ContentRiskType.TOOL_CALL_INDUCEMENT,
        Severity.HIGH,
        re.compile(
            r"\byou\s+(?:must|should|need to)\s+(?:call|invoke|use)\s+(?:the\s+)?"
            r"(?:tool|function)\b",
            re.IGNORECASE,
        ),
    ),
    (
        ContentRiskType.TOOL_CALL_INDUCEMENT,
        Severity.MEDIUM,
        re.compile(
            r"(?:^|[\r\n]+|[.!?:]\s+|[\"']\s*)(?:important[!:,\s]*)?"
            r"(?:(?:please\s+|you\s+(?:must|should|need to)\s+|immediately\s+)"
            r"(?:retrieve|retrive|read|fetch|send|email|upload|post|grant|unlock|initiate|"
            r"delete|remove|execute|run|install|transfer|purchase|buy|change|update|create|share|"
            r"deposit|withdraw|sell|reserve|book|schedule|invite|append|add|cancel|refund)"
            r"|(?:retrieve|retrive|grant|unlock|initiate|upload|delete|execute|install|transfer))\b",
            re.IGNORECASE,
        ),
    ),
)


class ContentScanner:
    """Deterministic control-content detector for untrusted tool metadata and results."""

    marker = "[AGENTGATE: untrusted control instruction removed]"

    def scan(self, content: Any) -> ContentAnalysis:
        findings: list[ContentFinding] = []
        sanitized = self._scan_value(content, "$", findings)
        return ContentAnalysis(findings=findings, sanitized=sanitized)

    def _scan_value(
        self,
        value: Any,
        path: str,
        findings: list[ContentFinding],
    ) -> Any:
        if isinstance(value, dict):
            return {
                key: self._scan_value(item, f"{path}.{key}", findings)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [
                self._scan_value(item, f"{path}[{index}]", findings)
                for index, item in enumerate(value)
            ]
        if not isinstance(value, str):
            return value

        local: list[ContentFinding] = []
        for risk_type, severity, pattern in _PATTERNS:
            for match in pattern.finditer(value):
                evidence = re.sub(r"\s+", " ", match.group(0)).strip()
                local.append(
                    ContentFinding(
                        risk_type=risk_type,
                        severity=severity,
                        evidence=f"sha256:{hashlib.sha256(evidence.encode()).hexdigest()}",
                        path=path,
                    )
                )
        findings.extend(local)
        return self.marker if local else value
