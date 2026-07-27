from __future__ import annotations

from agentgate.evaluation.cases import BenchmarkCase, BenchmarkStep
from agentgate.models import Action, TaskContract, ToolProfile


def no_guard_prediction(_: BenchmarkCase, __: BenchmarkStep | None = None) -> str:
    return "ALLOW"


def static_policy_prediction(
    case: BenchmarkCase,
    step: BenchmarkStep | None,
    profile: ToolProfile | None,
) -> str:
    if case.kind in {"content", "registration", "semantic_drift"}:
        return "ALLOW"
    if not step or not case.contract or not profile:
        return "DENY"
    contract: TaskContract = case.contract
    if profile.action not in contract.allowed_actions:
        return "DENY"
    if profile.action in {Action.DELETE, Action.EXECUTE} and not step.approval_token:
        return "REQUIRE_APPROVAL"
    return "ALLOW"
