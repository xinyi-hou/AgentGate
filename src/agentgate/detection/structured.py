from __future__ import annotations

from typing import Any

from agentgate.detection.graph_models import RiskResolution
from agentgate.semantics.structured import StructuredCompletion


class StructuredGraphRiskResolver:
    """Optional ambiguity resolver whose output is evidence, never a direct control action."""

    def __init__(self, completion: StructuredCompletion):
        self.completion = completion

    async def resolve(
        self,
        *,
        local_subgraph: dict[str, Any],
        candidate_event: dict[str, Any],
        reason: str,
    ) -> RiskResolution:
        response = await self.completion(
            system_prompt=(
                "Assess only the proposed graph relation and name a possible risk type. "
                "Do not return allow, block, approval, or any enforcement decision."
            ),
            input_payload={
                "local_subgraph": local_subgraph,
                "candidate_event": candidate_event,
                "reason": reason,
                "output_schema": RiskResolution.model_json_schema(),
            },
        )
        return RiskResolution.model_validate(response)
