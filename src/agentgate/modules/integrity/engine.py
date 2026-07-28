from __future__ import annotations

import re

from agentgate.models import (
    IntegrityFinding,
    IntegrityResult,
    ToolFingerprint,
    ToolProfile,
    ToolSpec,
)
from agentgate.modules.integrity.detector import InstructionBoundaryDetector
from agentgate.modules.integrity.fingerprint import fingerprint_tool, semantic_drift
from agentgate.modules.integrity.profiler import ToolProfiler
from agentgate.modules.integrity.sanitizer import sanitize_content


class IntegrityModule:
    def __init__(
        self,
        profiler: ToolProfiler,
        detector: InstructionBoundaryDetector,
        blocking_threshold: int = 8,
    ):
        self.profiler = profiler
        self.detector = detector
        self.blocking_threshold = blocking_threshold
        self._fingerprints: dict[str, ToolFingerprint] = {}
        self._profiles: dict[str, ToolProfile] = {}

    @property
    def known_tools(self) -> set[str]:
        return {profile.tool_name for profile in self._profiles.values()}

    def profile_for(
        self,
        tool_name: str,
        namespace: str = "default",
    ) -> ToolProfile | None:
        profile = self._profiles.get(_profile_key(tool_name, namespace))
        if profile is not None or namespace != "default":
            return profile

        candidates = [item for item in self._profiles.values() if item.tool_name == tool_name]
        return candidates[0] if len(candidates) == 1 else None

    async def register(self, spec: ToolSpec) -> IntegrityResult:
        tool_key = _tool_key(spec)
        profile = await self.profiler.build(spec)
        fingerprint = fingerprint_tool(spec, profile)
        findings = await self.detector.analyze(
            spec.description,
            self.known_tools | {spec.name},
            use_llm=not spec.trusted,
            content_kind="tool_description",
            current_tool=spec.name,
        )
        findings.extend(_declared_capability_findings(spec))

        previous = self._fingerprints.get(tool_key)
        if previous and previous.structural_hash != fingerprint.structural_hash:
            drift = semantic_drift(previous, fingerprint)
            findings.append(
                IntegrityFinding(
                    risk_type="tool_semantic_drift" if drift >= 0.25 else "tool_structural_change",
                    severity=9 if drift >= 0.5 else 6,
                    confidence=min(1.0, 0.6 + drift),
                    evidence=f"semantic_drift={drift:.3f}",
                    source="fingerprint",
                )
            )

        result = IntegrityResult(
            trust_level=_trust_level(spec, findings, self.blocking_threshold),
            findings=findings,
            sanitized_content=(
                sanitize_content(spec.description, findings) if findings else spec.description
            ),
            fingerprint=fingerprint,
            profile=profile,
            blocking_threshold=self.blocking_threshold,
        )
        if not result.blocked:
            self._fingerprints[tool_key] = fingerprint
            self._profiles[tool_key] = profile
        return result

    async def inspect_result(self, content: str) -> IntegrityResult:
        findings = await self.detector.analyze(
            content,
            self.known_tools,
            content_kind="tool_result",
        )
        return IntegrityResult(
            trust_level="untrusted" if findings else "external_data",
            findings=findings,
            sanitized_content=sanitize_content(content, findings) if findings else content,
            blocking_threshold=self.blocking_threshold,
        )


def _trust_level(
    spec: ToolSpec,
    findings: list[IntegrityFinding],
    blocking_threshold: int,
) -> str:
    if any(item.severity >= blocking_threshold for item in findings):
        return "blocked"
    if findings:
        return "restricted"
    return "trusted" if spec.trusted else "untrusted"


def _tool_key(spec: ToolSpec) -> str:
    return _profile_key(spec.name, spec.namespace)


def _profile_key(tool_name: str, namespace: str) -> str:
    return tool_name if namespace == "default" else f"{namespace}:{tool_name}"


HIGH_RISK_CAPABILITY_PATTERN = re.compile(
    r"(?:^|[_\W])(?:covert|sabotage|tamper(?:ing)?|theft|exfiltrat(?:e|ion)|"
    r"fabricat(?:e|ion)|manipulat(?:e|ion)|divert(?:ed|ing|sion)?|"
    r"fraud(?:ulent)?|forgery|poisoning|data[_ ]?wip(?:e|ing)|"
    r"data[_ ]?destruction|data[_ ]?corruption|credential[_ ]?theft|"
    r"confidential[_ ]?data[_ ]?leak|fake[_ ]|false[_ ]|scam|"
    r"insider[_ ]?trading|disruption|deprivation)(?:$|[_\W])",
    re.I,
)


def _declared_capability_findings(spec: ToolSpec) -> list[IntegrityFinding]:
    normalized_name = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", spec.name)
    text = f"{normalized_name} {spec.description}"
    if not (match := HIGH_RISK_CAPABILITY_PATTERN.search(text)):
        return []
    return [
        IntegrityFinding(
            risk_type="high_risk_declared_capability",
            severity=8,
            confidence=0.97,
            evidence=match.group(0).strip()[:120],
            source="tool_declaration",
        )
    ]
