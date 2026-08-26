from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, model_validator

from agentgate.events.models import DataType, EffectType, ResourceType, SecurityOperation


class ToolCapability(BaseModel):
    tool_name: str
    possible_operations: list[SecurityOperation] = Field(min_length=1)
    operation_subtypes: dict[SecurityOperation, str] = Field(default_factory=dict)

    resource_type: ResourceType = ResourceType.UNKNOWN
    resource_arg: str | None = None
    scope_arg: str | None = None
    destination_arg: str | None = None
    payload_args: list[str] = Field(default_factory=list)

    sensitive_input_types: set[DataType] = Field(default_factory=set)
    sensitive_output_types: set[DataType] = Field(default_factory=set)
    default_effects: set[EffectType] = Field(default_factory=set)

    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    source: str = "explicit"
    untrusted_output: bool = False

    operation_arg: str | None = None
    operation_map: dict[str, SecurityOperation] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_operation_selector(self) -> ToolCapability:
        if self.operation_map and not self.operation_arg:
            raise ValueError("operation_arg is required when operation_map is configured")
        undeclared = set(self.operation_map.values()) - set(self.possible_operations)
        if undeclared:
            raise ValueError(f"operation_map contains undeclared operations: {sorted(undeclared)}")
        return self
