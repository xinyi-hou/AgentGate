from __future__ import annotations

from datetime import timedelta
from hashlib import sha256

from agentgate.events.models import (
    DataType,
    EventPhase,
    SecurityOperation,
    ToolSecurityEvent,
    TrustDomain,
    utc_now,
)
from agentgate.state.counters import counter_delta
from agentgate.state.labels import labels_for_event
from agentgate.state.models import (
    SensitiveEventRef,
    SensitiveObject,
    SessionSecurityState,
    StateFact,
    StateStore,
)
from agentgate.state.provenance import fingerprints_for, sensitive_fragments


class StateManager:
    def __init__(
        self,
        store: StateStore,
        *,
        history_limit: int = 200,
        history_ttl_seconds: int = 3600,
        label_ttl_seconds: int = 3600,
    ):
        self.store = store
        self.history_limit = history_limit
        self.history_ttl = timedelta(seconds=history_ttl_seconds)
        self.label_ttl = timedelta(seconds=label_ttl_seconds)

    async def get(self, principal: str, session_id: str) -> SessionSecurityState:
        state = await self.store.get(principal, session_id)
        threshold = utc_now() - self.history_ttl
        state.recent_sensitive_events = [
            item for item in state.recent_sensitive_events if item.timestamp >= threshold
        ][-self.history_limit :]
        self._prune_labels(state, utc_now())
        return state

    async def observe(self, event: ToolSecurityEvent) -> SessionSecurityState:
        if event.phase != EventPhase.RESULT:
            raise ValueError("fact state can only be updated from RESULT events")

        def update(state: SessionSecurityState) -> SessionSecurityState:
            self._prune_labels(state, event.timestamp)
            for counter, amount in counter_delta(event).items():
                state.counters[counter] = state.counters.get(counter, 0) + amount
            if event.success:
                labels = labels_for_event(event)
                state.labels.update(labels)
                for label in labels:
                    state.label_facts.append(
                        StateFact(
                            fact_type="label",
                            value=label.value,
                            source_call_id=event.call_id,
                            task_id=event.task_id,
                            agent_id=event.agent_id,
                            created_at=event.timestamp,
                            expires_at=event.timestamp + self.label_ttl,
                        )
                    )
                produced = self._create_objects(event, state)
                for item in produced:
                    state.sensitive_objects[item.object_id] = item
                    if item.object_id not in event.data_objects:
                        event.data_objects.append(item.object_id)
                if _security_relevant(event):
                    state.recent_sensitive_events.append(_event_ref(event))
                    self._prune_history(state)
            return state

        return await self.store.update(event.principal, event.session_id, update)

    @staticmethod
    def _prune_labels(state: SessionSecurityState, now) -> None:
        had_facts = bool(state.label_facts)
        state.label_facts = [
            item for item in state.label_facts if item.expires_at is None or item.expires_at >= now
        ]
        if had_facts:
            active_values = {item.value for item in state.label_facts}
            state.labels = {label for label in state.labels if label.value in active_values}

    def _create_objects(
        self,
        event: ToolSecurityEvent,
        state: SessionSecurityState,
    ) -> list[SensitiveObject]:
        if not event.success or not event.data_types:
            return []
        if event.operation not in {SecurityOperation.READ, SecurityOperation.WRITE}:
            return []
        if (
            event.data_types == {DataType.PUBLIC}
            and not event.data_objects
            and not _external_or_untrusted_read(event)
        ):
            return []

        parents = [
            object_id for object_id in event.data_objects if object_id in state.sensitive_objects
        ]
        for object_id in parents:
            state.sensitive_objects[object_id].last_seen_at = event.timestamp
        produced: list[SensitiveObject] = []
        fragments = (
            sensitive_fragments(event.result, event.data_types)
            if event.operation == SecurityOperation.READ
            else []
        )
        candidates = [
            (path, value, data_type)
            for path, value, data_types in fragments
            for data_type in sorted(data_types, key=str)
        ]
        if not candidates:
            candidates = [
                (None, event.result, data_type)
                for data_type in sorted(event.data_types, key=str)
                if data_type != DataType.PUBLIC
                or event.data_objects
                or _external_or_untrusted_read(event)
            ]
        for path, value, data_type in candidates:
            fingerprints = fingerprints_for(value)
            if event.operation == SecurityOperation.WRITE and event.resource_id:
                fingerprints = sorted(set(fingerprints) | set(fingerprints_for(event.resource_id)))
            suffix = sha256(
                f"{event.call_id}:{path or '$'}:{data_type.value}".encode()
            ).hexdigest()[:16]
            produced.append(
                SensitiveObject(
                    object_id=f"D-{suffix}",
                    data_type=data_type,
                    sensitivity=data_type,
                    source_resource=event.resource_id,
                    source_field=path,
                    producer_call_id=event.call_id,
                    task_id=event.task_id,
                    agent_id=event.agent_id,
                    parent_object_ids=parents,
                    fingerprints=fingerprints,
                    created_at=event.timestamp,
                    last_seen_at=event.timestamp,
                )
            )
        return produced

    def _prune_history(self, state: SessionSecurityState) -> None:
        threshold = utc_now() - self.history_ttl
        state.recent_sensitive_events = [
            item for item in state.recent_sensitive_events if item.timestamp >= threshold
        ][-self.history_limit :]


def _security_relevant(event: ToolSecurityEvent) -> bool:
    return bool(
        event.data_types - {DataType.PUBLIC}
        or _external_or_untrusted_read(event)
        or event.effects
        or event.operation
        in {
            SecurityOperation.SEND,
            SecurityOperation.EXECUTE,
            SecurityOperation.DELETE,
            SecurityOperation.AUTH,
            SecurityOperation.PRIVILEGE,
            SecurityOperation.INSTALL,
        }
    )


def _external_or_untrusted_read(event: ToolSecurityEvent) -> bool:
    return event.operation == SecurityOperation.READ and (
        event.untrusted_context
        or event.trust_domain in {TrustDomain.TRUSTED_EXTERNAL, TrustDomain.UNKNOWN_EXTERNAL}
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
