from __future__ import annotations

from typing import Protocol

from agentgate.audit.models import AuditRecord


class AuditStore(Protocol):
    async def append(self, record: AuditRecord) -> None: ...

    async def query(
        self,
        *,
        principal: str | None = None,
        session_id: str | None = None,
    ) -> list[AuditRecord]: ...
