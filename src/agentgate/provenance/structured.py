from __future__ import annotations

from typing import Any

from agentgate.provenance.dependency import DependencyInference, DependencySource
from agentgate.semantics.structured import StructuredCompletion


class StructuredDependencyResolver:
    """Optional local-subgraph resolver; configure only inside an approved data boundary."""

    def __init__(self, completion: StructuredCompletion):
        self.completion = completion

    async def resolve(
        self,
        *,
        sources: list[DependencySource],
        target_arguments: dict[str, Any],
        target_tool: str,
        target_operation: str,
    ) -> list[DependencyInference]:
        response = await self.completion(
            system_prompt=(
                "Determine only whether each candidate source data object contributes to the "
                "target arguments. Do not decide risk or enforcement. Return strict JSON."
            ),
            input_payload={
                "sources": [item.model_dump(mode="json") for item in sources],
                "target": {
                    "tool": target_tool,
                    "operation": target_operation,
                    "arguments": target_arguments,
                },
                "output_item_schema": DependencyInference.model_json_schema(),
            },
        )
        if not isinstance(response, dict) or not isinstance(response.get("dependencies"), list):
            raise ValueError("dependency resolver must return a dependencies array")
        return [DependencyInference.model_validate(item) for item in response["dependencies"]]
