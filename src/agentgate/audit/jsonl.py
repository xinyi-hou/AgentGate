from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from agentgate.audit.models import AuditRecord
from agentgate.state.provenance import digest_payload

_SECRET_KEYS = {
    "password",
    "token",
    "approval_token",
    "credential",
    "secret",
    "api_key",
    "authorization",
}
_CONTENT_KEYS = {"arguments", "result", "output", "body", "content", "payload"}


class JsonlAuditStore:
    def __init__(self, path: str | Path, *, unsafe_debug_payloads: bool = False):
        self.path = Path(path)
        self.unsafe_debug_payloads = unsafe_debug_payloads
        self._lock = asyncio.Lock()

    async def append(self, record: AuditRecord) -> None:
        secured = record.model_copy(
            update={"payload": secure_payload(record.payload, self.unsafe_debug_payloads)}
        )
        rendered = json.dumps(secured.model_dump(mode="json"), ensure_ascii=False, default=str)
        async with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            await asyncio.to_thread(_append_line, self.path, rendered)

    async def query(
        self,
        *,
        principal: str | None = None,
        session_id: str | None = None,
    ) -> list[AuditRecord]:
        if not self.path.exists():
            return []
        async with self._lock:
            lines = await asyncio.to_thread(self.path.read_text, encoding="utf-8")
        records = [AuditRecord.model_validate_json(line) for line in lines.splitlines() if line]
        return [
            item
            for item in records
            if (principal is None or item.principal == principal)
            and (session_id is None or item.session_id == session_id)
        ]


def event_summary(event: Any, *, include_payloads: bool = False) -> dict[str, Any]:
    payload = event.model_dump(mode="json")
    if include_payloads:
        return payload
    arguments = payload.pop("arguments", None)
    result = payload.pop("result", None)
    resource = payload.pop("resource_id", None)
    destination = payload.pop("destination", None)
    if arguments is not None:
        payload["arguments_digest"] = digest_payload(arguments)
    if result is not None:
        payload["result_digest"] = digest_payload(result)
    if resource is not None:
        payload["resource_digest"] = digest_payload(resource)
    if destination is not None:
        payload["destination_digest"] = digest_payload(destination)
    return payload


def secure_payload(value: Any, unsafe_debug: bool, key: str = "") -> Any:
    lowered = key.lower()
    if any(secret == lowered or lowered.endswith(f"_{secret}") for secret in _SECRET_KEYS):
        return "[REDACTED]"
    if not unsafe_debug and lowered in _CONTENT_KEYS:
        return {"redacted": True, "sha256": digest_payload(value)}
    if isinstance(value, dict):
        return {
            str(item_key): secure_payload(item, unsafe_debug, str(item_key))
            for item_key, item in value.items()
        }
    if isinstance(value, list):
        return [secure_payload(item, unsafe_debug, key) for item in value]
    return value


def _append_line(path: Path, rendered: str) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(rendered + "\n")
