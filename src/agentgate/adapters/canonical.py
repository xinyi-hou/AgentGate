from __future__ import annotations

from typing import Any

from agentgate.events import RawToolCall
from agentgate.runtime.context import RuntimeContext
from agentgate.semantics import CanonicalToolCall


def canonicalize_call(
    raw_call: CanonicalToolCall | RawToolCall | dict[str, Any],
    context: RuntimeContext,
    *,
    source_framework: str,
    source_transport: str | None,
) -> CanonicalToolCall:
    if isinstance(raw_call, CanonicalToolCall):
        payload = raw_call.model_dump()
    elif isinstance(raw_call, RawToolCall):
        payload = CanonicalToolCall.from_raw(
            raw_call,
            source_framework=source_framework,
            source_transport=source_transport,
        ).model_dump()
    elif isinstance(raw_call, dict):
        payload = dict(raw_call)
        payload["principal_id"] = payload.pop("principal", context.principal)
        payload.setdefault("source_framework", source_framework)
        payload.setdefault("source_transport", source_transport)
    else:
        raise TypeError("tool call must be a mapping, RawToolCall, or CanonicalToolCall")

    payload.update(
        principal_id=context.principal,
        session_id=context.session_id,
        agent_id=context.agent_id,
        task_id=context.task_id,
        parent_call_id=context.parent_call_id,
        source_framework=source_framework,
        source_transport=source_transport,
    )
    return CanonicalToolCall.model_validate(payload)
