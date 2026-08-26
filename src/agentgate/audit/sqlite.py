from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path

from agentgate.audit.jsonl import secure_payload
from agentgate.audit.models import AuditRecord


class SqliteAuditStore:
    def __init__(self, path: str | Path, *, unsafe_debug_payloads: bool = False):
        self.path = Path(path)
        self.unsafe_debug_payloads = unsafe_debug_payloads
        self._lock = asyncio.Lock()

    async def append(self, record: AuditRecord) -> None:
        secured = record.model_copy(
            update={"payload": secure_payload(record.payload, self.unsafe_debug_payloads)}
        )
        async with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            await asyncio.to_thread(_insert, self.path, secured)

    async def query(
        self,
        *,
        principal: str | None = None,
        session_id: str | None = None,
    ) -> list[AuditRecord]:
        if not self.path.exists():
            return []
        async with self._lock:
            rows = await asyncio.to_thread(_query, self.path, principal, session_id)
        return [
            AuditRecord.model_validate(
                {
                    "record_id": row[0],
                    "event_type": row[1],
                    "principal": row[2],
                    "session_id": row[3],
                    "call_id": row[4],
                    "payload": json.loads(row[5]),
                    "timestamp": row[6],
                }
            )
            for row in rows
        ]


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_records (
            record_id TEXT PRIMARY KEY,
            event_type TEXT NOT NULL,
            principal TEXT NOT NULL,
            session_id TEXT NOT NULL,
            call_id TEXT,
            payload_json TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS audit_session_idx "
        "ON audit_records (principal, session_id, timestamp)"
    )
    return connection


def _insert(path: Path, record: AuditRecord) -> None:
    with _connect(path) as connection:
        connection.execute(
            "INSERT INTO audit_records VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                record.record_id,
                record.event_type.value,
                record.principal,
                record.session_id,
                record.call_id,
                json.dumps(record.payload, ensure_ascii=False, default=str),
                record.timestamp.isoformat(),
            ),
        )


def _query(
    path: Path,
    principal: str | None,
    session_id: str | None,
) -> list[tuple]:
    clauses: list[str] = []
    parameters: list[str] = []
    if principal is not None:
        clauses.append("principal = ?")
        parameters.append(principal)
    if session_id is not None:
        clauses.append("session_id = ?")
        parameters.append(session_id)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    query = f"SELECT * FROM audit_records{where} ORDER BY timestamp"
    with _connect(path) as connection:
        return connection.execute(query, parameters).fetchall()
