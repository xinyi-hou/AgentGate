from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field, field_validator

from agentgate.events.models import (
    DataType,
    EffectType,
    ResourceType,
    SecurityOperation,
    TrustDomain,
)
from agentgate.state.models import StateLabel


class DecisionAction(StrEnum):
    ALLOW = "ALLOW"
    AUDIT = "AUDIT"
    RESTRICT = "RESTRICT"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    BLOCK = "BLOCK"
    ISOLATE = "ISOLATE"


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SecurityDecision(BaseModel):
    action: DecisionAction
    rule_ids: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    rewritten_arguments: dict | None = None
    severity: Severity | None = None
    approval_id: str | None = None

    @property
    def permits_execution(self) -> bool:
        return self.action in {
            DecisionAction.ALLOW,
            DecisionAction.AUDIT,
            DecisionAction.RESTRICT,
        }


class EventCondition(BaseModel):
    operations: set[SecurityOperation] = Field(default_factory=set)
    data_types: set[DataType] = Field(default_factory=set)
    excluded_data_types: set[DataType] = Field(default_factory=set)
    trust_domains: set[TrustDomain] = Field(default_factory=set)
    resource_types: set[ResourceType] = Field(default_factory=set)
    effects: set[EffectType] = Field(default_factory=set)
    trusted_context: bool | None = None
    untrusted_context: bool | None = None


class EventRule(BaseModel):
    id: str
    name: str
    condition: EventCondition
    action: DecisionAction
    severity: Severity = Severity.HIGH
    reason: str

    @field_validator("action")
    @classmethod
    def validate_action(cls, value: DecisionAction) -> DecisionAction:
        return _validate_detection_action(value)


class StateRule(BaseModel):
    id: str
    name: str
    required_labels: set[StateLabel] = Field(default_factory=set)
    forbidden_labels: set[StateLabel] = Field(default_factory=set)
    condition: EventCondition
    action: DecisionAction
    severity: Severity = Severity.HIGH
    reason: str

    @field_validator("action")
    @classmethod
    def validate_action(cls, value: DecisionAction) -> DecisionAction:
        return _validate_detection_action(value)


class AggregateMetric(StrEnum):
    EVENT_COUNT = "EVENT_COUNT"
    AFFECTED_COUNT = "AFFECTED_COUNT"


class AggregateRule(BaseModel):
    id: str
    name: str
    condition: EventCondition
    metric: AggregateMetric = AggregateMetric.EVENT_COUNT
    threshold: int = Field(ge=1)
    window_seconds: int = Field(gt=0)
    action: DecisionAction
    severity: Severity = Severity.HIGH
    reason: str

    @field_validator("action")
    @classmethod
    def validate_action(cls, value: DecisionAction) -> DecisionAction:
        return _validate_detection_action(value)


class SequenceStep(EventCondition):
    pass


class SequenceConstraints(BaseModel):
    same_session: bool = True
    same_task: bool = False
    same_resource: bool = False
    same_object: bool = False
    same_destination: bool = False
    same_data: bool = False
    max_interval_seconds: int | None = None


class SequenceRule(BaseModel):
    id: str
    name: str
    sequence: list[SequenceStep] = Field(min_length=2)
    constraints: SequenceConstraints = Field(default_factory=SequenceConstraints)
    action: DecisionAction
    severity: Severity = Severity.HIGH
    reason: str

    @field_validator("action")
    @classmethod
    def validate_action(cls, value: DecisionAction) -> DecisionAction:
        return _validate_detection_action(value)


class SingleCallPolicy(BaseModel):
    dangerous_command_patterns: list[str] = Field(default_factory=list)
    dangerous_delete_resources: list[str] = Field(default_factory=list)
    command_argument_names: set[str] = Field(default_factory=lambda: {"command", "cmd"})
    max_scope: dict[SecurityOperation, int] = Field(default_factory=dict)


class ResourceAccessRule(BaseModel):
    id: str
    principals: list[str] = Field(default_factory=lambda: ["*"])
    operations: set[SecurityOperation] = Field(default_factory=set)
    resource_types: set[ResourceType] = Field(default_factory=set)
    resource_patterns: list[str] = Field(default_factory=lambda: ["*"])
    action: DecisionAction = DecisionAction.BLOCK
    severity: Severity = Severity.HIGH
    reason: str = "The principal is not authorized for this resource operation."

    @field_validator("action")
    @classmethod
    def validate_action(cls, value: DecisionAction) -> DecisionAction:
        if value not in {
            DecisionAction.REQUIRE_APPROVAL,
            DecisionAction.BLOCK,
            DecisionAction.ISOLATE,
        }:
            raise ValueError("resource access rules must enforce approval, block, or isolation")
        return value


class SecurityPolicy(BaseModel):
    single_call: SingleCallPolicy = Field(default_factory=SingleCallPolicy)
    event_rules: list[EventRule] = Field(default_factory=list)
    state_rules: list[StateRule] = Field(default_factory=list)
    aggregate_rules: list[AggregateRule] = Field(default_factory=list)
    access_rules: list[ResourceAccessRule] = Field(default_factory=list)
    sequence_rules: list[SequenceRule] = Field(default_factory=list)


def _validate_detection_action(value: DecisionAction) -> DecisionAction:
    if value in {DecisionAction.ALLOW, DecisionAction.RESTRICT}:
        raise ValueError("detection rules cannot allow calls or rewrite arguments")
    return value
