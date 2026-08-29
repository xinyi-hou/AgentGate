from __future__ import annotations

from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from agentgate.labels.models import SecurityLabel


class DependencySource(BaseModel):
    object_id: str
    source_resource: str | None = None
    source_field: str | None = None
    labels: set[SecurityLabel] = Field(default_factory=set)
    data_types: set[str] = Field(default_factory=set)


class DependencyInference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    object_id: str
    depends_on: bool
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str


class DependencyResolver(Protocol):
    async def resolve(
        self,
        *,
        sources: list[DependencySource],
        target_arguments: dict[str, Any],
        target_tool: str,
        target_operation: str,
    ) -> list[DependencyInference]: ...
