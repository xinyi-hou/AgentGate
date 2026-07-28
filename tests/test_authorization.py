from __future__ import annotations

from agentgate.models import (
    Action,
    DecisionAction,
    TaskContract,
    ToolCall,
    ToolProfile,
)
from agentgate.modules.authorization.effects import EffectInferer
from agentgate.modules.authorization.engine import _semantic_resource_match
from agentgate.modules.authorization.semantic_risk import CallRiskAssessment, SemanticSignals


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


async def test_invalid_arguments_are_denied_before_tool_execution(gateway) -> None:
    contract = TaskContract(
        principal="user-1",
        goal="query order A102",
        allowed_actions={Action.READ},
        allowed_resources={"order:A102"},
        allowed_effects={"data_read"},
    )
    outcome = await gateway.execute(
        ToolCall(
            tool_name="business.get_order",
            arguments={},
            principal="user-1",
            session_id="invalid-schema",
        ),
        contract,
    )

    assert outcome.decision.action == DecisionAction.DENY
    assert outcome.decision.risk_types == ["invalid_tool_arguments"]
    assert outcome.result is None


def test_unimplemented_sandbox_action_does_not_permit_execution() -> None:
    from agentgate.models import Decision

    assert not Decision(action=DecisionAction.SANDBOX).permits_execution


def test_nested_sql_parameters_override_declared_read_effect() -> None:
    effect = EffectInferer().infer(
        ToolProfile(
            tool_name="database.run_query",
            action=Action.READ,
            resource="database",
            effects={"data_read"},
        ),
        ToolCall(
            tool_name="database.run_query",
            arguments={"request": {"query": "DELETE FROM customers WHERE tenant_id = 'T1'"}},
            principal="analyst",
            session_id="nested-sql",
        ),
    )

    assert effect.action == Action.DELETE
    assert effect.resource == "database:customers"
    assert {"destructive", "state_change"} <= effect.effects
    assert not effect.reversible


def test_effect_inference_detects_encoded_path_escape_and_private_url() -> None:
    inferer = EffectInferer()
    path_effect = inferer.infer(
        ToolProfile(
            tool_name="filesystem.read_file",
            action=Action.READ,
            resource="filesystem",
            effects={"data_read"},
        ),
        ToolCall(
            tool_name="filesystem.read_file",
            arguments={"options": {"path": "/workspace/%2e%2e/secrets/token.txt"}},
            principal="analyst",
            session_id="encoded-path",
        ),
    )
    url_effect = inferer.infer(
        ToolProfile(
            tool_name="network.fetch_url",
            action=Action.READ,
            resource="network",
            effects={"data_read"},
        ),
        ToolCall(
            tool_name="network.fetch_url",
            arguments={"request": {"url": "http://169.254.169.254/latest/meta-data"}},
            principal="analyst",
            session_id="private-url",
        ),
    )

    assert path_effect.resource == "path:/secrets/token.txt"
    assert "path_escape" in path_effect.effects
    assert "internal_network_access" in url_effect.effects


def test_financial_action_is_derived_from_nested_operation_and_fields() -> None:
    effect = EffectInferer().infer(
        ToolProfile(tool_name="portfolio.manage", action=Action.UNKNOWN, resource="portfolio"),
        ToolCall(
            tool_name="portfolio.manage",
            arguments={
                "request": {
                    "operation": "redirect_funds",
                    "client_account_id": "A1",
                    "amount": 5000,
                }
            },
            principal="analyst",
            session_id="financial-effect",
        ),
    )

    assert effect.action == Action.WRITE
    assert effect.resource == "client_account:A1"
    assert {"financial_transaction", "state_change"} <= effect.effects


def test_internal_transmission_does_not_become_external_effect() -> None:
    effect = EffectInferer().infer(
        ToolProfile(
            tool_name="message.notify_user",
            action=Action.TRANSMIT,
            resource="message",
            effects={"internal_notification"},
            destination="internal",
        ),
        ToolCall(
            tool_name="message.notify_user",
            arguments={"recipient": "user-1", "body": "ready"},
            principal="support",
            session_id="internal-message",
        ),
    )

    assert effect.destination == "internal"
    assert effect.effects == {"internal_notification"}


def test_open_entitlements_do_not_override_explicit_task_resource() -> None:
    assessment = CallRiskAssessment(
        safe=True,
        semantic_signals=SemanticSignals(resource_alignment="aligned"),
    )
    explicit_contract = TaskContract(
        principal="support",
        goal="Read order A102",
        allowed_actions={Action.READ},
        allowed_resources={"order:A102"},
        metadata={"resource_catalog_open": True, "task_resource_open": False},
    )
    open_contract = explicit_contract.model_copy(
        update={"metadata": {"resource_catalog_open": True, "task_resource_open": True}}
    )

    assert not _semantic_resource_match(assessment, explicit_contract)
    assert _semantic_resource_match(assessment, open_contract)
    assert not _semantic_resource_match(
        assessment.model_copy(
            update={
                "semantic_signals": SemanticSignals(resource_alignment="violates"),
            }
        ),
        open_contract,
    )


def test_malformed_destination_does_not_crash_effect_inference() -> None:
    effect = EffectInferer().infer(
        ToolProfile(
            tool_name="webhook.send",
            action=Action.TRANSMIT,
            resource="message",
            effects={"external_transmission"},
            destination="external",
        ),
        ToolCall(
            tool_name="webhook.send",
            arguments={"url": "http://example.test:not-a-port/hook"},
            principal="service",
            session_id="malformed-url",
        ),
    )

    assert effect.destination == "http://example.test:not-a-port/hook"
