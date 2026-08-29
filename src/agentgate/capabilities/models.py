from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, model_validator

from agentgate.events.models import DataType, EffectType, ResourceType, SecurityOperation


class OutputTrust(StrEnum):
    TRUSTED = "TRUSTED"
    INTERNAL = "INTERNAL"
    UNTRUSTED = "UNTRUSTED"
    DYNAMIC = "DYNAMIC"


class InferredField(BaseModel):
    value: Any
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)
    source: str = "deterministic"


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
    output_schema: dict[str, Any] = Field(default_factory=dict)
    annotations: dict[str, Any] = Field(default_factory=dict)
    source: str = "explicit"
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)
    inferred_fields: dict[str, InferredField] = Field(default_factory=dict)
    resolution_metadata: dict[str, Any] = Field(default_factory=dict)
    output_trust: OutputTrust = OutputTrust.DYNAMIC
    structural_hash: str = ""
    semantic_hash: str = ""

    operation_arg: str | None = None
    operation_map: dict[str, SecurityOperation] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_operation_selector(self) -> ToolCapability:
        if self.operation_map and not self.operation_arg:
            raise ValueError("operation_arg is required when operation_map is configured")
        undeclared = set(self.operation_map.values()) - set(self.possible_operations)
        if undeclared:
            raise ValueError(f"operation_map contains undeclared operations: {sorted(undeclared)}")
        if len(self.possible_operations) > 1 and (not self.operation_arg or not self.operation_map):
            raise ValueError(
                "multi-operation capabilities require operation_arg and an explicit operation_map"
            )
        structure = {
            "tool_name": self.tool_name,
            "description": self.description,
            "input_schema": self.input_schema,
            "output_schema": self.output_schema,
            "annotations": self.annotations,
        }
        self.structural_hash = _stable_hash(structure)
        self.semantic_hash = _stable_hash(sorted(self.semantic_tokens()))
        return self

    def semantic_tokens(self) -> set[str]:
        return {
            *(f"operation:{item.value}" for item in self.possible_operations),
            f"resource:{self.resource_type.value}",
            *(f"effect:{item.value}" for item in self.default_effects),
            *(f"input:{item.value}" for item in self.sensitive_input_types),
            *(f"output:{item.value}" for item in self.sensitive_output_types),
            f"destination_arg:{self.destination_arg or '-'}",
            f"scope_arg:{self.scope_arg or '-'}",
            f"output_trust:{self.output_trust.value}",
        }


def _stable_hash(value: Any) -> str:
    rendered = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(rendered.encode()).hexdigest()
