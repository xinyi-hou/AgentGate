from __future__ import annotations

import asyncio
import hashlib
import secrets
from datetime import timedelta

from agentgate.enforcement.models import ApprovalRequest, ApprovalStatus
from agentgate.events.models import RawToolCall, utc_now
from agentgate.state.provenance import digest_payload


class MemoryApprovalStore:
    def __init__(self) -> None:
        self.items: dict[str, ApprovalRequest] = {}
        self.lock = asyncio.Lock()


class ApprovalManager:
    def __init__(self, store: MemoryApprovalStore | None = None, *, ttl_seconds: int = 300):
        self.store = store or MemoryApprovalStore()
        self.ttl = timedelta(seconds=ttl_seconds)

    async def ensure_request(self, call: RawToolCall) -> ApprovalRequest:
        digest = digest_payload(call.arguments)
        async with self.store.lock:
            self._expire_locked()
            for item in self.store.items.values():
                if (
                    item.principal == call.principal
                    and item.session_id == call.session_id
                    and item.call_id == call.call_id
                    and item.tool_name == call.tool_name
                    and item.argument_digest == digest
                    and item.status in {ApprovalStatus.PENDING, ApprovalStatus.APPROVED}
                ):
                    return item.model_copy(deep=True)
            item = ApprovalRequest(
                principal=call.principal,
                session_id=call.session_id,
                call_id=call.call_id,
                tool_name=call.tool_name,
                argument_digest=digest,
                expires_at=utc_now() + self.ttl,
            )
            self.store.items[item.approval_id] = item
            return item.model_copy(deep=True)

    async def get(self, approval_id: str) -> ApprovalRequest:
        async with self.store.lock:
            self._expire_locked()
            try:
                return self.store.items[approval_id].model_copy(deep=True)
            except KeyError as exc:
                raise KeyError(f"unknown approval: {approval_id}") from exc

    async def approve(self, approval_id: str) -> tuple[ApprovalRequest, str]:
        async with self.store.lock:
            self._expire_locked()
            item = self._pending_locked(approval_id)
            token = secrets.token_urlsafe(32)
            item.status = ApprovalStatus.APPROVED
            item.token_hash = _token_hash(token)
            item.decided_at = utc_now()
            return item.model_copy(deep=True), token

    async def deny(self, approval_id: str) -> ApprovalRequest:
        async with self.store.lock:
            self._expire_locked()
            item = self._pending_locked(approval_id)
            item.status = ApprovalStatus.DENIED
            item.decided_at = utc_now()
            return item.model_copy(deep=True)

    async def consume(self, call: RawToolCall) -> bool:
        if not call.approval_token:
            return False
        digest = digest_payload(call.arguments)
        async with self.store.lock:
            self._expire_locked()
            for item in self.store.items.values():
                if (
                    item.status == ApprovalStatus.APPROVED
                    and item.principal == call.principal
                    and item.session_id == call.session_id
                    and item.call_id == call.call_id
                    and item.tool_name == call.tool_name
                    and item.argument_digest == digest
                    and item.token_hash is not None
                    and secrets.compare_digest(item.token_hash, _token_hash(call.approval_token))
                ):
                    item.status = ApprovalStatus.CONSUMED
                    item.consumed_at = utc_now()
                    return True
            return False

    def _pending_locked(self, approval_id: str) -> ApprovalRequest:
        try:
            item = self.store.items[approval_id]
        except KeyError as exc:
            raise KeyError(f"unknown approval: {approval_id}") from exc
        if item.status != ApprovalStatus.PENDING:
            raise ValueError(f"approval is not pending: {item.status.value}")
        return item

    def _expire_locked(self) -> None:
        now = utc_now()
        for item in self.store.items.values():
            if (
                item.status in {ApprovalStatus.PENDING, ApprovalStatus.APPROVED}
                and now >= item.expires_at
            ):
                item.status = ApprovalStatus.EXPIRED


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
