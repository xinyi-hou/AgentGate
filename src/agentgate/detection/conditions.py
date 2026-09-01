from __future__ import annotations

from typing import Any

from agentgate.policy.models import EventCondition


def event_matches(event: Any, condition: EventCondition) -> bool:
    actions = list(getattr(event, "actions", []) or [])
    if actions and any(_action_matches(action, condition) for action in actions):
        return _optional_bool_matches(event, "untrusted_context", condition.untrusted_context)
    return _action_matches(event, condition) and _optional_bool_matches(
        event, "untrusted_context", condition.untrusted_context
    )


def _action_matches(action: Any, condition: EventCondition) -> bool:
    data_types = set(getattr(action, "data_types", set()))
    effects = set(getattr(action, "effects", set()))
    return bool(
        (not condition.operations or action.operation in condition.operations)
        and (not condition.data_types or bool(data_types & condition.data_types))
        and not bool(data_types & condition.excluded_data_types)
        and (
            not condition.trust_domains
            or getattr(action, "trust_domain", None) in condition.trust_domains
        )
        and (
            not condition.resource_types
            or getattr(action, "resource_type", None) in condition.resource_types
        )
        and (not condition.effects or bool(effects & condition.effects))
    )


def _optional_bool_matches(event: Any, field: str, expected: bool | None) -> bool:
    return expected is None or getattr(event, field, None) is expected
