from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from agentgate.models import Action, Sensitivity


@dataclass
class GraphNode:
    node_id: str
    kind: str
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    source: str
    target: str
    relation: str
    labels: set[Sensitivity] = field(default_factory=set)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class SessionState:
    session_id: str
    principal: str
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)
    labels_by_value: dict[str, set[Sensitivity]] = field(default_factory=dict)
    personal_records_read: int = 0
    external_transmissions: int = 0
    privileged_operations: int = 0
    used_approvals: set[str] = field(default_factory=set)
    actions: list[Action] = field(default_factory=list)
    isolated: bool = False
    reservations: dict[str, ExecutionReservation] = field(default_factory=dict)


@dataclass
class ExecutionReservation:
    personal_records: int = 0
    external_transmissions: int = 0
    privileged_operations: int = 0
    approval_token: str | None = None


class InMemoryStateStore:
    def __init__(self):
        self.sessions: dict[tuple[str, str], SessionState] = {}
        self.used_approvals: set[str] = set()
        self.lock = asyncio.Lock()

    def get(self, session_id: str, principal: str) -> SessionState:
        key = (principal, session_id)
        state = self.sessions.get(key)
        if state is None:
            state = SessionState(session_id=session_id, principal=principal)
            self.sessions[key] = state
        return state
