from __future__ import annotations

from pydantic import BaseModel

from agentgate.events.models import ToolExecutionResult, ToolSecurityEvent
from agentgate.policy.models import SecurityDecision


class RuntimeOutcome(BaseModel):
    decision: SecurityDecision
    request_event: ToolSecurityEvent
    execution: ToolExecutionResult | None = None
    result_event: ToolSecurityEvent | None = None
    state_updated: bool = False
