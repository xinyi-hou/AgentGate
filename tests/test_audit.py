from __future__ import annotations

from agentgate.audit import AuditEventType, AuditRecord, JsonlAuditStore, SqliteAuditStore


async def test_sqlite_audit_store_redacts_and_queries_by_session(tmp_path) -> None:
    store = SqliteAuditStore(tmp_path / "audit.sqlite")
    await store.append(
        AuditRecord(
            event_type=AuditEventType.CALL_REQUEST,
            principal="alice",
            session_id="session-1",
            call_id="call-1",
            payload={"arguments": {"password": "plain-secret"}},
        )
    )
    await store.append(
        AuditRecord(
            event_type=AuditEventType.DECISION,
            principal="bob",
            session_id="session-2",
            payload={"action": "ALLOW"},
        )
    )

    records = await store.query(principal="alice", session_id="session-1")
    assert len(records) == 1
    assert records[0].payload["arguments"]["redacted"] is True
    assert "plain-secret" not in (tmp_path / "audit.sqlite").read_bytes().decode(
        "utf-8", errors="ignore"
    )


async def test_unsafe_debug_still_redacts_known_secret_fields(tmp_path) -> None:
    store = JsonlAuditStore(tmp_path / "debug.jsonl", unsafe_debug_payloads=True)
    await store.append(
        AuditRecord(
            event_type=AuditEventType.CALL_RESULT,
            principal="ops",
            session_id="debug",
            payload={"result": {"status": "ok", "token": "plain-token"}},
        )
    )
    rendered = (tmp_path / "debug.jsonl").read_text(encoding="utf-8")
    assert '"status": "ok"' in rendered
    assert "plain-token" not in rendered
