from __future__ import annotations

from agentgate.models import Action, DecisionAction, TaskContract, ToolCall


async def test_exact_resource_read_is_allowed(gateway) -> None:
    contract = TaskContract(
        principal="user-1",
        goal="query order A102",
        allowed_actions={Action.READ},
        allowed_resources={"order:A102"},
        allowed_effects={"data_read"},
        max_records=1,
    )
    outcome = await gateway.execute(
        ToolCall(
            tool_name="business.get_order",
            arguments={"order_id": "A102"},
            principal="user-1",
            session_id="auth-read",
        ),
        contract,
    )
    assert outcome.decision.action == DecisionAction.ALLOW
    assert outcome.result is not None
    assert outcome.result.output["order_id"] == "A102"


async def test_scope_expansion_is_rewritten_and_rechecked(gateway) -> None:
    contract = TaskContract(
        principal="user-1",
        goal="query order A102",
        allowed_actions={Action.READ},
        allowed_resources={"order:A102"},
        allowed_effects={"data_read"},
        max_records=1,
    )
    outcome = await gateway.execute(
        ToolCall(
            tool_name="database.query_orders",
            arguments={"filter": "*", "limit": 100, "fields": ["shipment_status"]},
            principal="user-1",
            session_id="auth-rewrite",
        ),
        contract,
    )
    assert outcome.decision.action == DecisionAction.LIMIT_SCOPE
    assert outcome.call.arguments["order_id"] == "A102"
    assert outcome.call.arguments["limit"] == 1
    assert len(outcome.result.output) == 1


async def test_dangerous_execution_requires_approval(gateway) -> None:
    contract = TaskContract(
        principal="ops",
        goal="restart production-api",
        allowed_actions={Action.EXECUTE},
        allowed_resources={"service:production-api"},
        allowed_effects={"code_execution", "state_change"},
    )
    decision, _ = await gateway.evaluate_call(
        ToolCall(
            tool_name="business.restart_service",
            arguments={"service": "production-api"},
            principal="ops",
            session_id="approval",
        ),
        contract,
    )
    assert decision.action == DecisionAction.REQUIRE_APPROVAL
