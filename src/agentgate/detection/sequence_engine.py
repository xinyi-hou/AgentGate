from __future__ import annotations

from datetime import datetime, timedelta

from pydantic import BaseModel, Field

from agentgate.detection.conditions import event_matches
from agentgate.detection.models import DetectionState, DetectionStateStore, RuleMatchState
from agentgate.events.models import EventPhase, ToolSecurityEvent, utc_now
from agentgate.policy.models import SequenceConstraints, SequenceRule, SequenceStep
from agentgate.state.models import SensitiveEventRef, SensitiveObject, SessionSecurityState


class RuleMatch(BaseModel):
    rule_id: str
    call_ids: list[str]
    object_ids: list[str] = Field(default_factory=list)
    relation_evidence: list[str] = Field(default_factory=list)


class SequenceEngine:
    """Incremental NFA whose rule progress is stored outside session facts."""

    def __init__(
        self,
        rules: list[SequenceRule],
        store: DetectionStateStore,
        policy_version: str,
        *,
        max_active_paths: int = 200,
    ):
        self.rules = rules
        self.store = store
        self.policy_version = policy_version
        self.max_active_paths = max_active_paths

    async def get_state(self, principal: str, session_id: str) -> DetectionState:
        state = await self.store.get(principal, session_id, self.policy_version)
        return _unexpired_state(state, utc_now())

    async def evaluate(
        self,
        event: ToolSecurityEvent,
        facts: SessionSecurityState,
        detection_state: DetectionState | None = None,
    ) -> list[tuple[SequenceRule, RuleMatch]]:
        """Preview a REQUEST without changing facts or rule matching progress."""
        progress_by_rule = detection_state
        if progress_by_rule is None:
            progress_by_rule = await self.get_state(event.principal, event.session_id)
        current = _event_ref(event)
        matches: list[tuple[SequenceRule, RuleMatch]] = []
        for rule in self.rules:
            for progress in progress_by_rule.get(rule.id, []):
                if progress.next_step != len(rule.sequence) - 1:
                    continue
                if not _matches_step(current, rule.sequence[progress.next_step]):
                    continue
                selected = [*progress.matched_events, current]
                if not _constraints_hold(selected, rule.constraints, facts.sensitive_objects):
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
                            relation_evidence=_relation_evidence(rule.constraints),
                        ),
                    )
                )
                break
        return matches

    async def observe(
        self,
        event: ToolSecurityEvent,
        facts: SessionSecurityState,
    ) -> DetectionState:
        """Advance rule state only from a successful RESULT after fact state is updated."""
        if event.phase != EventPhase.RESULT or event.success is not True:
            raise ValueError("detection state can only advance from successful RESULT events")
        current = _event_ref(event)

        def update(stored: DetectionState) -> DetectionState:
            next_state: DetectionState = {}
            for rule in self.rules:
                active = _unexpired(
                    stored.get(rule.id, []),
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
                    if not _constraints_hold(selected, rule.constraints, facts.sensitive_objects):
                        continue
                    next_step = progress.next_step + 1
                    if next_step < len(rule.sequence):
                        next_active.append(
                            _progress(
                                event,
                                rule,
                                next_step,
                                selected,
                                started_at=progress.started_at,
                                policy_version=self.policy_version,
                            )
                        )

                if _matches_step(current, rule.sequence[0]) and len(rule.sequence) > 1:
                    next_active.append(
                        _progress(
                            event,
                            rule,
                            1,
                            [current],
                            started_at=current.timestamp,
                            policy_version=self.policy_version,
                        )
                    )
                deduplicated = _deduplicate(next_active)[-self.max_active_paths :]
                if deduplicated:
                    next_state[rule.id] = deduplicated
            return next_state

        return await self.store.update(
            event.principal,
            event.session_id,
            self.policy_version,
            update,
        )


def _progress(
    event: ToolSecurityEvent,
    rule: SequenceRule,
    next_step: int,
    matched: list[SensitiveEventRef],
    *,
    started_at: datetime,
    policy_version: str,
) -> RuleMatchState:
    interval = rule.constraints.max_interval_seconds
    return RuleMatchState(
        principal=event.principal,
        session_id=event.session_id,
        rule_id=rule.id,
        policy_version=policy_version,
        next_step=next_step,
        matched_call_ids=[item.call_id for item in matched],
        matched_object_ids=sorted({object_id for item in matched for object_id in item.object_ids}),
        matched_events=matched,
        started_at=started_at,
        updated_at=event.timestamp,
        expires_at=(started_at + timedelta(seconds=interval) if interval else None),
    )


def _event_ref(event: ToolSecurityEvent) -> SensitiveEventRef:
    return SensitiveEventRef(
        call_id=event.call_id,
        task_id=event.task_id,
        agent_id=event.agent_id,
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
    progress: list[RuleMatchState],
    current_time: datetime,
    max_interval_seconds: int | None,
) -> list[RuleMatchState]:
    if max_interval_seconds is None:
        return progress
    return [
        item
        for item in progress
        if 0 <= (current_time - item.started_at).total_seconds() <= max_interval_seconds
    ]


def _unexpired_state(state: DetectionState, now: datetime) -> DetectionState:
    return {
        rule_id: [item for item in paths if item.expires_at is None or now <= item.expires_at]
        for rule_id, paths in state.items()
        if any(item.expires_at is None or now <= item.expires_at for item in paths)
    }


def _deduplicate(progress: list[RuleMatchState]) -> list[RuleMatchState]:
    unique: dict[tuple[str, int, tuple[str, ...]], RuleMatchState] = {}
    for item in progress:
        key = (item.rule_id, item.next_step, tuple(item.matched_call_ids))
        unique[key] = item
    return list(unique.values())


def _constraints_hold(
    events: list[SensitiveEventRef],
    constraints: SequenceConstraints,
    objects: dict[str, SensitiveObject],
) -> bool:
    if constraints.same_task and len({item.task_id for item in events}) != 1:
        return False
    if constraints.same_agent and len({item.agent_id for item in events}) != 1:
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
    if constraints.data_dependency and not all(
        _events_share_lineage(left, right, objects)
        for left, right in zip(events, events[1:], strict=False)
    ):
        return False
    return True


def _relation_evidence(constraints: SequenceConstraints) -> list[str]:
    evidence = ["same_session"]
    for enabled, name in (
        (constraints.same_task, "same_task"),
        (constraints.same_agent, "same_agent"),
        (constraints.same_resource, "same_resource"),
        (constraints.same_object, "same_object"),
        (constraints.same_destination, "same_destination"),
        (constraints.data_dependency, "data_dependency"),
    ):
        if enabled:
            evidence.append(name)
    if constraints.max_interval_seconds is not None:
        evidence.append(f"max_interval_seconds:{constraints.max_interval_seconds}")
    return evidence


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
