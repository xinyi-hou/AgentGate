from __future__ import annotations

from typing import Any, Protocol

from agentgate.events.models import SecurityOperation
from agentgate.semantics.models import SemanticResolution


class StructuredCompletion(Protocol):
    async def __call__(
        self,
        *,
        system_prompt: str,
        input_payload: dict[str, Any],
    ) -> dict[str, Any]: ...


class StructuredSemanticResolver:
    """Provider-neutral adapter for schema-constrained semantic fact extraction."""

    def __init__(self, completion: StructuredCompletion):
        self.completion = completion

    async def resolve(
        self,
        *,
        name: str,
        description: str,
        input_schema: dict[str, Any],
        output_schema: dict[str, Any],
        candidates: list[SecurityOperation],
        reason: str,
    ) -> SemanticResolution:
        response = await self.completion(
            system_prompt=(
                "Extract behavior-neutral tool capability facts. Do not classify intent, risk, "
                "maliciousness, or an enforcement action. Return only the requested JSON schema."
            ),
            input_payload={
                "tool": {
                    "name": name,
                    "description": description,
                    "input_schema": input_schema,
                    "output_schema": output_schema,
                },
                "deterministic_candidates": [item.value for item in candidates],
                "resolution_reason": reason,
                "allowed_operations": [item.value for item in SecurityOperation],
                "output_schema": SemanticResolution.model_json_schema(),
            },
        )
        return SemanticResolution.model_validate(response)
