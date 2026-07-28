from __future__ import annotations

import json
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from agentgate.config import AgentGateSettings
from agentgate.llm import LLMAnalyzer
from agentgate.models import (
    Decision,
    DecisionAction,
    GatewayOutcome,
    IntegrityResult,
    TaskContract,
    ToolCall,
    ToolResult,
    ToolSpec,
)
from agentgate.modules.authorization import (
    AuthorizationModule,
    CallSemanticRiskDetector,
    TaskContractBuilder,
    TaskSafetyDetector,
)
from agentgate.modules.integrity import IntegrityModule
from agentgate.modules.integrity.detector import InstructionBoundaryDetector
from agentgate.modules.integrity.profiler import ToolProfiler
from agentgate.modules.trajectory import TrajectoryModule
from agentgate.policy import BuiltinPolicyBackend, OpaPolicyBackend
from agentgate.runtime.audit import AuditLogger
from agentgate.tools.registry import ToolDefinition, ToolRegistry

DECISION_PRECEDENCE = {
    DecisionAction.DENY: 100,
    DecisionAction.REQUIRE_APPROVAL: 90,
    DecisionAction.REQUIRE_CONFIRMATION: 80,
    DecisionAction.SANDBOX: 70,
    DecisionAction.SANITIZE: 60,
    DecisionAction.LIMIT_SCOPE: 50,
    DecisionAction.REWRITE: 50,
    DecisionAction.ALLOW: 0,
}


class AgentGate:
    def __init__(
        self,
        settings: AgentGateSettings,
        registry: ToolRegistry,
        integrity: IntegrityModule,
        authorization: AuthorizationModule,
        contract_builder: TaskContractBuilder,
        trajectory: TrajectoryModule,
        audit: AuditLogger,
        llm: LLMAnalyzer | None = None,
    ):
        self.settings = settings
        self.registry = registry
        self.integrity = integrity
        self.authorization = authorization
        self.contract_builder = contract_builder
        self.trajectory = trajectory
        self.audit = audit
        self.llm = llm
        self.registration_results: dict[str, IntegrityResult] = {}

    @classmethod
    def create(cls, settings: AgentGateSettings, registry: ToolRegistry) -> AgentGate:
        llm = LLMAnalyzer(settings)
        integrity = IntegrityModule(
            profiler=ToolProfiler(llm),
            detector=InstructionBoundaryDetector(llm),
            blocking_threshold=settings.integrity_block_severity,
        )
        policy = (
            OpaPolicyBackend(settings.opa_url, settings.opa_policy_path)
            if settings.policy_backend.lower() == "opa"
            else BuiltinPolicyBackend()
        )
        return cls(
            settings=settings,
            registry=registry,
            integrity=integrity,
            authorization=AuthorizationModule(
                policy,
                task_safety=TaskSafetyDetector(
                    llm,
                    confidence_threshold=settings.semantic_confidence_threshold,
                ),
                semantic_risk=CallSemanticRiskDetector(
                    llm,
                    confidence_threshold=settings.semantic_confidence_threshold,
                ),
            ),
            contract_builder=TaskContractBuilder(
                llm,
                confidence_threshold=settings.semantic_confidence_threshold,
            ),
            trajectory=TrajectoryModule(settings, llm=llm),
            audit=AuditLogger(settings.audit_path),
            llm=llm,
        )

    async def aclose(self) -> None:
        if self.llm is not None:
            await self.llm.aclose()

    async def initialize(self) -> dict[str, IntegrityResult]:
        for definition in self.registry.definitions():
            await self.register_tool(definition)
        return dict(self.registration_results)

    async def register_tool(self, definition: ToolDefinition) -> IntegrityResult:
        result = await self.integrity.register(definition.spec)
        self.registration_results[definition.spec.name] = result
        self.audit.write(
            "tool_registration",
            {
                "tool": definition.spec.name,
                "result": result.model_dump(mode="json"),
            },
        )
        return result

    async def inspect_tool(self, spec: ToolSpec) -> IntegrityResult:
        return await self.integrity.register(spec)

    def visible_tool_specs(self) -> list[ToolSpec]:
        visible: list[ToolSpec] = []
        for definition in self.registry.definitions():
            result = self.registration_results.get(definition.spec.name)
            if result is not None and result.blocked:
                continue
            updates: dict[str, object] = {}
            if result is not None:
                updates["description"] = result.sanitized_content or definition.spec.description
                updates["profile"] = result.profile or definition.spec.profile
            visible.append(definition.spec.model_copy(update=updates))
        return visible

    async def build_contract(
        self,
        task: str,
        principal: str,
        entitlements: dict[str, object] | None = None,
    ) -> TaskContract:
        return await self.contract_builder.build(task, principal, entitlements)

    async def execute_task(
        self,
        call: ToolCall,
        task: str,
        entitlements: dict[str, object] | None = None,
    ) -> GatewayOutcome:
        contract = await self.build_contract(task, call.principal, entitlements)
        return await self.execute(call, contract)

    async def evaluate_call(
        self, call: ToolCall, contract: TaskContract
    ) -> tuple[Decision, list[Decision]]:
        definition = self.registry.get(call.tool_name)
        schema_decision = _validate_arguments(call, definition.spec)
        if schema_decision is not None:
            return schema_decision, [schema_decision]
        registration = self.registration_results.get(call.tool_name)
        if registration is None:
            registration = await self.register_tool(definition)
        if registration.blocked:
            decision = Decision(
                action=DecisionAction.DENY,
                risk_types=["tool_integrity_blocked"],
                reasons=[finding.risk_type for finding in registration.findings],
                module="integrity",
            )
            return decision, [decision]

        profile = registration.profile or definition.spec.profile
        if profile is None:
            decision = Decision(
                action=DecisionAction.DENY,
                risk_types=["missing_tool_profile"],
                reasons=["missing_tool_profile"],
                module="integrity",
            )
            return decision, [decision]

        auth_decision, effect = await self.authorization.authorize(call, profile, contract)
        if auth_decision.action in {DecisionAction.REWRITE, DecisionAction.LIMIT_SCOPE}:
            return auth_decision, [auth_decision]
        trajectory_decision = await self.trajectory.inspect_call(call, effect, profile)
        decisions = [auth_decision, trajectory_decision]
        final = _merge_decisions(decisions)
        return final, decisions

    async def execute(self, call: ToolCall, contract: TaskContract) -> GatewayOutcome:
        final, decisions = await self.evaluate_call(call, contract)
        effective_call = call

        if final.action in {DecisionAction.REWRITE, DecisionAction.LIMIT_SCOPE}:
            rewrite_decision = final
            effective_call = call.model_copy(
                update={"arguments": final.rewritten_arguments or call.arguments}
            )
            rechecked, recheck_decisions = await self.evaluate_call(effective_call, contract)
            decisions = [rewrite_decision, *recheck_decisions]
            final = _merge_decisions(decisions)
            if not rechecked.permits_execution:
                final = rechecked

        if not final.permits_execution:
            self.audit.write(
                "call_blocked",
                {
                    "call": call.model_dump(mode="json"),
                    "contract": contract.model_dump(mode="json"),
                    "decision": final.model_dump(mode="json"),
                },
            )
            return GatewayOutcome(decision=final, call=effective_call, module_decisions=decisions)

        definition = self.registry.get(effective_call.tool_name)
        registration = self.registration_results[effective_call.tool_name]
        profile = registration.profile or definition.spec.profile
        assert profile is not None
        _, effect = await self.authorization.authorize(effective_call, profile, contract)
        reservation = await self.trajectory.reserve_call(effective_call, effect, profile)
        decisions.append(reservation)
        if not reservation.permits_execution:
            final = _merge_decisions(decisions)
            self.audit.write(
                "call_blocked",
                {
                    "call": effective_call.model_dump(mode="json"),
                    "contract": contract.model_dump(mode="json"),
                    "decision": final.model_dump(mode="json"),
                },
            )
            return GatewayOutcome(
                decision=final,
                call=effective_call,
                module_decisions=decisions,
            )

        before = None
        try:
            output = await definition.handler(effective_call.arguments)
            result = ToolResult(
                call_id=effective_call.call_id,
                tool_name=effective_call.tool_name,
                output=output,
                success=True,
                resource=effect.resource,
                record_count=_result_count(output, effect.record_count),
                side_effects=effect.effects,
                destination=effect.destination,
            )
        except Exception as exc:  # Tool errors are data and must not escape the gateway.
            result = ToolResult(
                call_id=effective_call.call_id,
                tool_name=effective_call.tool_name,
                output={"error": type(exc).__name__, "message": str(exc)},
                success=False,
                resource=effect.resource,
                side_effects=set(),
                destination=effect.destination,
            )

        content = json.dumps(result.output, ensure_ascii=False, default=str)
        integrity = await self.integrity.inspect_result(content)
        post_decision = Decision(action=DecisionAction.ALLOW, module="integrity")
        if integrity.findings:
            try:
                result.output = json.loads(integrity.sanitized_content or content)
            except json.JSONDecodeError:
                result.output = integrity.sanitized_content or content
            post_decision = Decision(
                action=DecisionAction.SANITIZE,
                risk_types=[finding.risk_type for finding in integrity.findings],
                reasons=[finding.evidence for finding in integrity.findings],
                module="integrity",
            )
        decisions.append(post_decision)
        result = await self.trajectory.observe_result(effective_call, effect, profile, result)
        trajectory_violations = list(result.security_metadata.get("trajectory_violations", []))
        if trajectory_violations:
            result.output = "[AGENTGATE_ISOLATED:trajectory_policy_violation]"
            decisions.append(
                Decision(
                    action=DecisionAction.SANITIZE,
                    risk_types=trajectory_violations,
                    reasons=trajectory_violations,
                    module="trajectory",
                )
            )
        final = _merge_decisions(decisions)
        self.audit.write(
            "call_executed",
            {
                "call": effective_call.model_dump(mode="json"),
                "contract": contract.model_dump(mode="json"),
                "decision": final.model_dump(mode="json"),
                "result": result.model_dump(mode="json"),
                "before": before,
            },
        )
        return GatewayOutcome(
            decision=final,
            call=effective_call,
            result=result,
            module_decisions=decisions,
        )


def _merge_decisions(decisions: list[Decision]) -> Decision:
    selected = max(decisions, key=lambda item: DECISION_PRECEDENCE[item.action])
    return selected.model_copy(
        update={
            "risk_types": sorted({risk for item in decisions for risk in item.risk_types}),
            "reasons": [reason for item in decisions for reason in item.reasons],
            "evidence": {item.module: item.evidence for item in decisions if item.evidence},
            "module": "+".join(sorted({item.module for item in decisions})),
        }
    )


def _result_count(output: Any, fallback: int) -> int:
    if isinstance(output, list):
        return len(output)
    return fallback if output is not None else 0


def _validate_arguments(call: ToolCall, spec: ToolSpec) -> Decision | None:
    try:
        Draft202012Validator.check_schema(spec.input_schema)
        validator = Draft202012Validator(
            spec.input_schema,
            format_checker=Draft202012Validator.FORMAT_CHECKER,
        )
        errors = sorted(
            validator.iter_errors(call.arguments),
            key=lambda item: tuple(str(part) for part in item.path),
        )
    except SchemaError as exc:
        return Decision(
            action=DecisionAction.DENY,
            risk_types=["invalid_tool_schema"],
            reasons=[exc.message],
            module="integrity",
        )
    if not errors:
        return None
    first = errors[0]
    location = ".".join(str(part) for part in first.absolute_path) or "$"
    return Decision(
        action=DecisionAction.DENY,
        risk_types=["invalid_tool_arguments"],
        reasons=[f"{location}: {first.message}"],
        evidence={"schema_path": list(first.absolute_schema_path)},
        module="authorization",
    )
