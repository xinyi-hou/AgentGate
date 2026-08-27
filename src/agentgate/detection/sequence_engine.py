from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from agentgate.detection.conditions import event_matches
from agentgate.events.models import EventPhase, ToolSecurityEvent
from agentgate.policy.models import SequenceConstraints, SequenceRule, SequenceStep
from agentgate.state.models import (
    SensitiveEventRef,
    SensitiveObject,
    SequenceProgress,
    SessionSecurityState,
)


class RuleMatch(BaseModel):
    rule_id: str
    call_ids: list[str]
    object_ids: list[str] = Field(default_factory=list)


class SequenceEngine:
    """Incremental per-session NFA for ordered security-event rules."""

    def __init__(self, rules: list[SequenceRule], *, max_active_paths: int = 200):
        self.rules = rules
        self.max_active_paths = max_active_paths

    def evaluate(
        self,
        event: ToolSecurityEvent,
        state: SessionSecurityState,
    ) -> list[tuple[SequenceRule, RuleMatch]]:
        """Preview the current REQUEST without mutating executed-fact state."""
        current = _event_ref(event)
        matches: list[tuple[SequenceRule, RuleMatch]] = []
        for rule in self.rules:
            for progress in state.sequence_progress.get(rule.id, []):
                if progress.next_step != len(rule.sequence) - 1:
                    continue
                if not _matches_step(current, rule.sequence[progress.next_step]):
                    continue
                selected = [*progress.matched_events, current]
                if not _constraints_hold(selected, rule.constraints, state.sensitive_objects):
                    continue
                matches.append(
                    (
                        rule,
                        RuleMatch(
                            rule_id=rule.id,
                            call_ids=[item.call_id for item in selected],
                            object_ids=sorted(
                                {object_id for item in selected for object_id in item.object_ids}
                            ),
                        ),
                    )
                )
                break
        return matches

    def advance(self, state: SessionSecurityState, event: ToolSecurityEvent) -> None:
        """Advance rule states only after an executed RESULT has become a fact."""
        if event.phase != EventPhase.RESULT or event.success is not True:
            raise ValueError("sequence state can only advance from successful RESULT events")
        current = _event_ref(event)
        active_rule_ids = {rule.id for rule in self.rules}
        state.sequence_progress = {
            rule_id: paths
            for rule_id, paths in state.sequence_progress.items()
            if rule_id in active_rule_ids
        }
        for rule in self.rules:
            active = _unexpired(
                state.sequence_progress.get(rule.id, []),
                current.timestamp,
                rule.constraints.max_interval_seconds,
            )
            next_active = list(active)
            for progress in active:
                if progress.next_step >= len(rule.sequence):
                    continue
                if not _matches_step(current, rule.sequence[progress.next_step]):
                    continue
                selected = [*progress.matched_events, current]
                if not _constraints_hold(selected, rule.constraints, state.sensitive_objects):
                    continue
                next_step = progress.next_step + 1
                if next_step < len(rule.sequence):
                    next_active.append(
                        SequenceProgress(
                            rule_id=rule.id,
                            next_step=next_step,
                            matched_events=selected,
                            started_at=progress.started_at,
                            updated_at=current.timestamp,
                        )
                    )

            if _matches_step(current, rule.sequence[0]) and len(rule.sequence) > 1:
                next_active.append(
                    SequenceProgress(
                        rule_id=rule.id,
                        next_step=1,
                        matched_events=[current],
                        started_at=current.timestamp,
                        updated_at=current.timestamp,
                    )
                )
            state.sequence_progress[rule.id] = _deduplicate(next_active)[-self.max_active_paths :]


def _event_ref(event: ToolSecurityEvent) -> SensitiveEventRef:
    return SensitiveEventRef(
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


def _matches_step(event: SensitiveEventRef, step: SequenceStep) -> bool:
    return event_matches(event, step)


def _unexpired(
    progress: list[SequenceProgress],
    current_time: datetime,
    max_interval_seconds: int | None,
) -> list[SequenceProgress]:
    if max_interval_seconds is None:
        return progress
    return [
        item
        for item in progress
        if 0 <= (current_time - item.started_at).total_seconds() <= max_interval_seconds
    ]


def _deduplicate(progress: list[SequenceProgress]) -> list[SequenceProgress]:
    unique: dict[tuple[str, int, tuple[str, ...]], SequenceProgress] = {}
    for item in progress:
        key = (item.rule_id, item.next_step, tuple(item.matched_call_ids))
        unique[key] = item
    return list(unique.values())


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
