from __future__ import annotations

import asyncio
from datetime import datetime, timedelta

from agentgate.detection.models import DetectionState, DetectionStateUpdater
from agentgate.events.models import utc_now


class MemoryDetectionStateStore:
    def __init__(self, ttl_seconds: int = 3600):
        self.ttl = timedelta(seconds=ttl_seconds)
        self._states: dict[tuple[str, str, str], tuple[DetectionState, datetime]] = {}
        self._lock = asyncio.Lock()

    async def get(
        self,
        principal: str,
        session_id: str,
        policy_version: str,
    ) -> DetectionState:
        async with self._lock:
            return self._get(principal, session_id, policy_version)

    async def update(
        self,
        principal: str,
        session_id: str,
        policy_version: str,
        updater: DetectionStateUpdater,
    ) -> DetectionState:
        async with self._lock:
            current = self._get(principal, session_id, policy_version)
            updated = updater(
                {
                    key: [item.model_copy(deep=True) for item in value]
                    for key, value in current.items()
                }
            )
            self._states[(principal, session_id, policy_version)] = (
                {
                    key: [item.model_copy(deep=True) for item in value]
                    for key, value in updated.items()
                },
                utc_now(),
            )
            return {
                key: [item.model_copy(deep=True) for item in value]
                for key, value in updated.items()
            }

    async def delete(self, principal: str, session_id: str) -> None:
        async with self._lock:
            for key in [key for key in self._states if key[:2] == (principal, session_id)]:
                self._states.pop(key, None)

    def _get(self, principal: str, session_id: str, policy_version: str) -> DetectionState:
        key = (principal, session_id, policy_version)
        stored = self._states.get(key)
        if stored is None:
            return {}
        state, updated_at = stored
        if utc_now() - updated_at > self.ttl:
            self._states.pop(key, None)
            return {}
        return {
            name: [item.model_copy(deep=True) for item in paths] for name, paths in state.items()
        }
