from __future__ import annotations

from pydantic import BaseModel, Field

from agentgate.content import ContentFinding
from agentgate.events.models import ToolExecutionResult, ToolSecurityEvent
from agentgate.policy.models import SecurityDecision


class RuntimeOutcome(BaseModel):
    decision: SecurityDecision
    request_event: ToolSecurityEvent
    execution: ToolExecutionResult | None = None
    result_event: ToolSecurityEvent | None = None
    state_updated: bool = False
    detection_state_updated: bool = False
    content_findings: list[ContentFinding] = Field(default_factory=list)
    result_sanitized: bool = False
    advisory_only: bool = False
