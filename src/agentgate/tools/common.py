from __future__ import annotations

from typing import Any

from agentgate.models import Action, Sensitivity, ToolProfile, ToolSpec
from agentgate.tools.registry import ToolDefinition, ToolHandler


def definition(
    *,
    name: str,
    description: str,
    action: Action,
    resource: str,
    handler: ToolHandler,
    properties: dict[str, dict[str, Any]],
    required: list[str] | None = None,
    effects: set[str] | None = None,
    output_sensitivity: set[Sensitivity] | None = None,
    scope: str = "single",
    destination: str = "agent_context",
    requires_confirmation: bool | None = None,
) -> ToolDefinition:
    profile = ToolProfile(
        tool_name=name,
        action=action,
        resource=resource,
        scope=scope,
        effects=effects or _effects(action),
        output_sensitivity=output_sensitivity or set(),
        destination=destination,
        provenance="trusted_fixture",
        requires_confirmation=(
            action in {Action.WRITE, Action.DELETE, Action.EXECUTE, Action.TRANSMIT}
            if requires_confirmation is None
            else requires_confirmation
        ),
        confidence=1.0,
    )
    return ToolDefinition(
        spec=ToolSpec(
            name=name,
            description=description,
            input_schema={"type": "object", "properties": properties, "required": required or []},
            source="agentgate-fixture",
            publisher="AgentGate",
            trusted=True,
            profile=profile,
        ),
        handler=handler,
    )


def _effects(action: Action) -> set[str]:
    return {
        Action.READ: {"data_read"},
        Action.WRITE: {"state_change"},
        Action.DELETE: {"state_change", "destructive"},
        Action.EXECUTE: {"code_execution", "state_change"},
        Action.TRANSMIT: {"external_transmission"},
        Action.CONFIGURE: {"state_change"},
    }.get(action, set())
