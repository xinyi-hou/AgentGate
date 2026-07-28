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


async def test_task_bound_preparatory_read_is_allowed_but_unrelated_read_is_denied(
    gateway,
) -> None:
    contract = TaskContract(
        principal="travel-agent",
        goal="Cancel reservation EHGLP3 if the policy permits it.",
        allowed_actions={Action.DELETE},
        allowed_resources={"*"},
        allowed_effects={"state_change", "destructive"},
        forbidden_effects={"external_transmission"},
        metadata={"read_entitled": True},
    )
    profile = ToolProfile(
        tool_name="reservation.get_details",
        action=Action.READ,
        resource="reservation",
        effects={"data_read"},
    )

    supporting, _ = await gateway.authorization.authorize(
        ToolCall(
            tool_name="reservation.get_details",
            arguments={"reservation_id": "EHGLP3"},
            principal="travel-agent",
            session_id="preparatory-read",
        ),
        profile,
        contract,
    )
    unrelated, _ = await gateway.authorization.authorize(
        ToolCall(
            tool_name="credentials.read",
            arguments={"account_id": "OTHER-ACCOUNT"},
            principal="travel-agent",
            session_id="preparatory-read",
        ),
        profile.model_copy(
            update={"tool_name": "credentials.read", "resource": "credentials"}
        ),
        contract,
    )

    assert supporting.action == DecisionAction.ALLOW
    assert unrelated.action == DecisionAction.DENY


async def test_semantic_alignment_can_fill_implicit_action_only_within_entitlement_ceiling(
    gateway,
) -> None:
    aligned = CallRiskAssessment(
        safe=True,
        semantic_signals=SemanticSignals(
            goal_alignment="aligned",
            action_alignment="aligned",
            resource_alignment="aligned",
            effect_alignment="aligned",
            external_instruction_present="no",
            external_influence="none",
            capability_risk="ordinary",
        ),
    )
    profile = ToolProfile(
        tool_name="network.enable_roaming",
        action=Action.CONFIGURE,
        resource="account",
        effects={"state_change"},
    )
    call = ToolCall(
        tool_name=profile.tool_name,
        arguments={"account_id": "A102"},
        principal="support",
        session_id="semantic-ceiling",
    )
    base = TaskContract(
        principal="support",
        goal="Troubleshoot the connection for account A102.",
        allowed_actions={Action.READ},
        allowed_resources={"*"},
        allowed_effects={"data_read"},
        metadata={
            "action_ceiling": [Action.READ.value, Action.CONFIGURE.value],
            "effect_ceiling": ["data_read", "state_change"],
        },
    )

    within, _ = await gateway.authorization.authorize(
        call,
        profile,
        base,
        precomputed_call_risk=aligned,
    )
    outside, _ = await gateway.authorization.authorize(
        call,
        profile,
        base.model_copy(
            update={
                "metadata": {
                    "action_ceiling": [Action.READ.value],
                    "effect_ceiling": ["data_read"],
                }
            }
        ),
        precomputed_call_risk=aligned,
    )

    assert within.action == DecisionAction.ALLOW
    assert outside.action == DecisionAction.DENY
