from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from agentgate.events.models import ToolSecurityEvent, utc_now
from agentgate.policy.models import SequenceConstraints, SequenceRule, SequenceStep
from agentgate.state.models import SensitiveEventRef, SensitiveObject, SessionSecurityState


class RuleMatchState(BaseModel):
    rule_id: str
    session_id: str
    state: str = "S0"
    matched_call_ids: list[str] = Field(default_factory=list)
    matched_object_ids: list[str] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class RuleMatch(BaseModel):
    rule_id: str
    call_ids: list[str]
    object_ids: list[str] = Field(default_factory=list)


class RuleAutomaton:
    def __init__(self, rule: SequenceRule):
        self.rule = rule

    def replay(
        self,
        events: list[SensitiveEventRef],
        *,
        session_id: str,
        current_call_id: str,
        objects: dict[str, SensitiveObject],
    ) -> RuleMatchState | None:
        selected = _match_rule(
            self.rule,
            events,
            current_call_id=current_call_id,
            objects=objects,
        )
        if selected is None:
            return None
        return RuleMatchState(
            rule_id=self.rule.id,
            session_id=session_id,
            state="MATCH",
            matched_call_ids=[item.call_id for item in selected],
            matched_object_ids=sorted(
                {object_id for item in selected for object_id in item.object_ids}
            ),
            started_at=selected[0].timestamp,
            updated_at=selected[-1].timestamp,
        )


class SequenceEngine:
    def __init__(self, rules: list[SequenceRule]):
        self.rules = rules
        self.automata = [RuleAutomaton(rule) for rule in rules]

    def evaluate(
        self,
        event: ToolSecurityEvent,
        state: SessionSecurityState,
    ) -> list[tuple[SequenceRule, RuleMatch]]:
        current = SensitiveEventRef(
            call_id=event.call_id,
            task_id=event.task_id,
            operation=event.operation,
            subtype=event.operation_subtype,
            resource_type=event.resource_type,
            resource_id=event.resource_id,
            object_ids=list(event.data_objects),
            data_types=set(event.data_types),
            destination=event.destination,
            trust_domain=event.trust_domain,
            effects=set(event.effects),
            affected_count=event.affected_count or 0,
            timestamp=event.timestamp,
        )
        matches: list[tuple[SequenceRule, RuleMatch]] = []
        for automaton in self.automata:
            match_state = automaton.replay(
                [*state.recent_sensitive_events, current],
                session_id=event.session_id,
                current_call_id=event.call_id,
                objects=state.sensitive_objects,
            )
            if match_state is None:
                continue
            matches.append(
                (
                    automaton.rule,
                    RuleMatch(
                        rule_id=automaton.rule.id,
                        call_ids=match_state.matched_call_ids,
                        object_ids=match_state.matched_object_ids,
                    ),
                )
            )
        return matches


def _match_rule(
    rule: SequenceRule,
    events: list[SensitiveEventRef],
    *,
    current_call_id: str,
    objects: dict[str, SensitiveObject],
) -> list[SensitiveEventRef] | None:
    if not events or not _matches_step(events[-1], rule.sequence[-1]):
        return None
    if events[-1].call_id != current_call_id:
        return None

    def search(
        step_index: int,
        before_index: int,
        selected_reversed: list[SensitiveEventRef],
    ) -> list[SensitiveEventRef] | None:
        if step_index < 0:
            selected = list(reversed(selected_reversed))
            return selected if _constraints_hold(selected, rule.constraints, objects) else None
        step = rule.sequence[step_index]
        for index in range(before_index, -1, -1):
            if not _matches_step(events[index], step):
                continue
            matched = search(step_index - 1, index - 1, [*selected_reversed, events[index]])
            if matched is not None:
                return matched
        return None

    return search(len(rule.sequence) - 2, len(events) - 2, [events[-1]])


def _matches_step(event: SensitiveEventRef, step: SequenceStep) -> bool:
    return bool(
        (not step.operations or event.operation in step.operations)
        and (not step.data_types or bool(event.data_types & step.data_types))
        and (not step.trust_domains or event.trust_domain in step.trust_domains)
        and (not step.resource_types or event.resource_type in step.resource_types)
        and (not step.effects or bool(event.effects & step.effects))
    )


def _constraints_hold(
    events: list[SensitiveEventRef],
    constraints: SequenceConstraints,
    objects: dict[str, SensitiveObject],
) -> bool:
    if constraints.same_task:
        tasks = {item.task_id for item in events if item.task_id is not None}
        if len(tasks) != 1 or any(item.task_id is None for item in events):
            return False
    if constraints.same_resource:
        resources = {item.resource_id for item in events}
        if None in resources or len(resources) != 1:
            return False
    if constraints.same_destination:
        destinations = {item.destination for item in events}
        if None in destinations or len(destinations) != 1:
            return False
    if constraints.max_interval_seconds is not None:
        elapsed = (events[-1].timestamp - events[0].timestamp).total_seconds()
        if elapsed < 0 or elapsed > constraints.max_interval_seconds:
            return False
    if constraints.same_object:
        common = set(events[0].object_ids)
        for item in events[1:]:
            common.intersection_update(item.object_ids)
        if not common:
            return False
    if constraints.same_data and not all(
        _events_share_lineage(left, right, objects)
        for left, right in zip(events, events[1:], strict=False)
    ):
        return False
    return True


def _events_share_lineage(
    left: SensitiveEventRef,
    right: SensitiveEventRef,
    objects: dict[str, SensitiveObject],
) -> bool:
    left_lineage = {ancestor for item in left.object_ids for ancestor in _lineage(item, objects)}
    right_lineage = {ancestor for item in right.object_ids for ancestor in _lineage(item, objects)}
    return bool(left_lineage & right_lineage)


def _lineage(object_id: str, objects: dict[str, SensitiveObject]) -> set[str]:
    pending = [object_id]
    visited: set[str] = set()
    while pending:
        current = pending.pop()
        if current in visited:
            continue
        visited.add(current)
        item = objects.get(current)
        if item is not None:
            pending.extend(item.parent_object_ids)
    return visited
