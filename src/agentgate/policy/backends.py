from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

import httpx

from agentgate.models import DecisionAction


class PolicyBackend(ABC):
    @abstractmethod
    async def decide(self, policy_input: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError


class BuiltinPolicyBackend(PolicyBackend):
    async def decide(self, policy_input: dict[str, Any]) -> dict[str, Any]:
        checks = policy_input.get("checks", {})
        failed = [name for name, matched in checks.items() if not matched]
        if failed:
            return {
                "action": DecisionAction.DENY,
                "reasons": [f"{name}_mismatch" for name in failed],
            }
        if policy_input.get("requires_approval") and not policy_input.get("approval_valid"):
            return {
                "action": DecisionAction.REQUIRE_APPROVAL,
                "reasons": ["approval_required"],
            }
        if policy_input.get("requires_confirmation") and not policy_input.get("confirmed"):
            return {
                "action": DecisionAction.REQUIRE_CONFIRMATION,
                "reasons": ["confirmation_required"],
            }
        return {"action": DecisionAction.ALLOW, "reasons": []}


class OpaPolicyBackend(PolicyBackend):
    def __init__(self, base_url: str, policy_path: str, timeout: float = 5.0):
        self.url = f"{base_url.rstrip('/')}/v1/data/{policy_path.strip('/')}"
        self.timeout = timeout

    async def decide(self, policy_input: dict[str, Any]) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(self.url, json={"input": policy_input})
            response.raise_for_status()
        body = response.json()
        if "result" not in body:
            return {"action": DecisionAction.DENY, "reasons": ["opa_undefined_decision"]}
        result = body["result"]
        if isinstance(result, bool):
            return {
                "action": DecisionAction.ALLOW if result else DecisionAction.DENY,
                "reasons": [] if result else ["opa_denied"],
            }
        return result
