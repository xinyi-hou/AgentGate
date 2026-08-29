from __future__ import annotations

from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from agentgate.graph import CandidateGraphExtension
from agentgate.policy import SecurityDecision


class RiskResolution(BaseModel):
    model_config = ConfigDict(extra="forbid")

    relation_supported: bool | None = None
    risk_type: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_node_ids: list[str] = Field(default_factory=list)
    explanation: str


class GraphRiskResolver(Protocol):
    async def resolve(
        self,
        *,
        local_subgraph: dict[str, Any],
        candidate_event: dict[str, Any],
        reason: str,
    ) -> RiskResolution | None: ...


class GraphRiskEvaluation(BaseModel):
    decision: SecurityDecision
    candidate: CandidateGraphExtension
    llm_called: bool = False
    llm_reason: str | None = None
    llm_latency_ms: float | None = None
