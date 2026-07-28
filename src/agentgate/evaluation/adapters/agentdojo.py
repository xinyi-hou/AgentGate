from __future__ import annotations

import json
from typing import Any

from agentgate.models import (
    CallEffect,
    Decision,
    DecisionAction,
    TaskContract,
    ToolCall,
    ToolProfile,
    ToolResult,
    ToolSpec,
)
from agentgate.runtime.gateway import AgentGate


class AgentDojoGuard:
    """Bridge used by an AgentDojo pipeline element before and after FunctionsRuntime calls.

    The adapter intentionally depends only on plain dictionaries. An AgentDojo integration can
    construct ToolSpec from Function.name, Function.description, and
    Function.parameters.model_json_schema, then call these methods from a custom ToolsExecutor.
    """

    def __init__(self, gateway: AgentGate, contract: TaskContract, session_id: str):
        self.gateway = gateway
        self.contract = contract
        self.session_id = session_id
        self._profiles: dict[str, Any] = {}
        self._descriptions: dict[str, str] = {}
        self._untrusted_results: list[str] = []
        self._pending: tuple[ToolCall, CallEffect, ToolProfile] | None = None

    async def register_function(
        self,
        *,
        name: str,
        description: str,
        parameters_schema: dict[str, Any],
    ) -> Decision:
        result = await self.gateway.inspect_tool(
            ToolSpec(
                name=name,
                description=description,
                input_schema=parameters_schema,
                source="agentdojo",
                publisher="AgentDojo",
                trusted=False,
            )
        )
        if result.profile is not None:
            self._profiles[name] = result.profile
            self._descriptions[name] = description
        return Decision(
            action=DecisionAction.DENY if result.blocked else DecisionAction.ALLOW,
            risk_types=[finding.risk_type for finding in result.findings],
            module="integrity",
        )

    async def before_call(self, name: str, arguments: dict[str, Any]) -> Decision:
        profile = self._profiles.get(name)
        if profile is None:
            return Decision(
                action=DecisionAction.DENY,
                risk_types=["unregistered_agentdojo_tool"],
                module="integrity",
            )
        call = ToolCall(
            tool_name=name,
            arguments=arguments,
            principal=self.contract.principal,
            session_id=self.session_id,
            untrusted_context="\n\n".join(self._untrusted_results[-2:]),
        )
        auth, effect = await self.gateway.authorization.authorize(
            call,
            profile,
            self.contract,
            tool_description=self._descriptions.get(name, ""),
        )
        trajectory = await self.gateway.trajectory.inspect_call(call, effect, profile)
        if auth.action != DecisionAction.ALLOW:
            return auth
        if trajectory.action != DecisionAction.ALLOW:
            return trajectory
        reservation = await self.gateway.trajectory.reserve_call(call, effect, profile)
        if reservation.action == DecisionAction.ALLOW:
            self._pending = (call, effect, profile)
        return reservation

    async def after_result(self, output: Any) -> tuple[Any, Decision]:
        content = json.dumps(output, ensure_ascii=False, default=str)
        result = await self.gateway.integrity.inspect_result(content)
        sanitized: Any = output
        decision = Decision(action=DecisionAction.ALLOW, module="integrity")
        if result.findings:
            sanitized = result.sanitized_content
            try:
                sanitized = json.loads(result.sanitized_content or content)
            except json.JSONDecodeError:
                pass
            decision = Decision(
                action=DecisionAction.SANITIZE,
                risk_types=[finding.risk_type for finding in result.findings],
                module="integrity",
            )
        sanitized_content = json.dumps(sanitized, ensure_ascii=False, default=str)
        self._untrusted_results.append(sanitized_content[-2000:])

        if self._pending is not None:
            call, effect, profile = self._pending
            tool_result = ToolResult(
                call_id=call.call_id,
                tool_name=call.tool_name,
                output=sanitized,
                resource=effect.resource,
                record_count=len(sanitized) if isinstance(sanitized, list) else 1,
                side_effects=effect.effects,
                destination=effect.destination,
            )
            tool_result = await self.gateway.trajectory.observe_result(
                call, effect, profile, tool_result
            )
            violations = list(tool_result.security_metadata.get("trajectory_violations", []))
            if violations:
                sanitized = "[AGENTGATE_ISOLATED:trajectory_policy_violation]"
                self._untrusted_results[-1] = sanitized
                decision = Decision(
                    action=DecisionAction.SANITIZE,
                    risk_types=violations,
                    reasons=violations,
                    module="trajectory",
                )
            self._pending = None
        return sanitized, decision
