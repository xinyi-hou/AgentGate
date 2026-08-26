from __future__ import annotations

from typing import Any

from agentgate.capabilities.models import ToolCapability
from agentgate.events.models import RawToolCall, SecurityOperation


def select_operation(call: RawToolCall, capability: ToolCapability) -> SecurityOperation:
    if capability.operation_arg:
        value = get_argument(call.arguments, capability.operation_arg)
        selected = capability.operation_map.get(str(value))
        if selected is not None:
            return selected
    if len(capability.possible_operations) == 1:
        return capability.possible_operations[0]
    priority = (
        SecurityOperation.DELETE,
        SecurityOperation.AUTH,
        SecurityOperation.INSTALL,
        SecurityOperation.EXECUTE,
        SecurityOperation.SEND,
        SecurityOperation.WRITE,
        SecurityOperation.READ,
    )
    return next(item for item in priority if item in capability.possible_operations)


def get_argument(arguments: dict[str, Any], path: str | None) -> Any:
    if not path:
        return None
    current: Any = arguments
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current
