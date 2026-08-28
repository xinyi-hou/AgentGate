from __future__ import annotations

from pydantic import BaseModel, Field

from agentgate.capabilities.models import ToolCapability
from agentgate.events.models import DataType, EffectType, ResourceType, SecurityOperation


class CapabilityGold(BaseModel):
    tool_name: str
    operations: set[SecurityOperation]
    resource_type: ResourceType
    resource_arg: str | None = None
    scope_arg: str | None = None
    destination_arg: str | None = None
    payload_args: set[str] = Field(default_factory=set)
    input_types: set[DataType] = Field(default_factory=set)
    output_types: set[DataType] = Field(default_factory=set)
    effects: set[EffectType] = Field(default_factory=set)


class CapabilityEvaluation(BaseModel):
    tool_name: str
    field_matches: dict[str, bool]

    @property
    def accuracy(self) -> float:
        return sum(self.field_matches.values()) / len(self.field_matches)


def evaluate_capability(
    capability: ToolCapability,
    gold: CapabilityGold,
) -> CapabilityEvaluation:
    if capability.tool_name != gold.tool_name:
        raise ValueError("capability and gold tool names differ")
    return CapabilityEvaluation(
        tool_name=gold.tool_name,
        field_matches={
            "operation": set(capability.possible_operations) == gold.operations,
            "resource_type": capability.resource_type == gold.resource_type,
            "resource_arg": capability.resource_arg == gold.resource_arg,
            "scope_arg": capability.scope_arg == gold.scope_arg,
            "destination_arg": capability.destination_arg == gold.destination_arg,
            "payload_args": set(capability.payload_args) == gold.payload_args,
            "sensitive_input_types": capability.sensitive_input_types == gold.input_types,
            "sensitive_output_types": capability.sensitive_output_types == gold.output_types,
            "effects": capability.default_effects == gold.effects,
        },
    )
