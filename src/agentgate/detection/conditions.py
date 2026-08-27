from __future__ import annotations

from typing import Any

from agentgate.policy.models import EventCondition


def event_matches(event: Any, condition: EventCondition) -> bool:
    data_types = set(getattr(event, "data_types", set()))
    effects = set(getattr(event, "effects", set()))
    return bool(
        (not condition.operations or event.operation in condition.operations)
        and (not condition.data_types or bool(data_types & condition.data_types))
        and not bool(data_types & condition.excluded_data_types)
        and (
            not condition.trust_domains
            or getattr(event, "trust_domain", None) in condition.trust_domains
        )
        and (
            not condition.resource_types
            or getattr(event, "resource_type", None) in condition.resource_types
        )
        and (not condition.effects or bool(effects & condition.effects))
        and _optional_bool_matches(event, "trusted_context", condition.trusted_context)
        and _optional_bool_matches(event, "untrusted_context", condition.untrusted_context)
    )


def _optional_bool_matches(event: Any, field: str, expected: bool | None) -> bool:
    return expected is None or getattr(event, field, None) is expected
