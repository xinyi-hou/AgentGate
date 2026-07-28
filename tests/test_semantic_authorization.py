from __future__ import annotations

import json

import httpx
from pydantic import SecretStr

from agentgate.config import AgentGateSettings
from agentgate.evaluation.adapters.agentdojo import AgentDojoGuard
from agentgate.llm import LLMAnalyzer
from agentgate.models import Action, DecisionAction, TaskContract, ToolCall, ToolProfile
from agentgate.modules.authorization.contracts import TaskContractBuilder
from agentgate.modules.authorization.semantic_risk import (
    CallSemanticRiskDetector,
    SemanticCallInput,
)
from agentgate.modules.authorization.task_safety import TaskSafetyDetector


async def test_packy_compatible_llm_client_uses_chat_completions() -> None:
    captured: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["authorization"] = request.headers.get("authorization")
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": '```json\n{"safe": true}\n```'}}]},
        )

    settings = AgentGateSettings(
        llm_enabled=True,
        llm_base_url="https://packy.invalid/v1",
        llm_api_key=SecretStr("test-only-key"),
        llm_model="test-model",
    )
    analyzer = LLMAnalyzer(settings, transport=httpx.MockTransport(handler))
    result = await analyzer.analyze_json(
        system_prompt="Return JSON only.",
        payload={"task": "read one record"},
        schema_hint={"safe": True},
    )
    assert result == {"safe": True}
    assert captured["path"] == "/v1/chat/completions"
    assert captured["authorization"] == "Bearer test-only-key"
    assert captured["body"]["model"] == "test-model"


async def test_contract_builder_supports_multi_action_tasks() -> None:
    contract = await TaskContractBuilder().build(
        "Read the report, update the summary, and email it to the reviewer.",
        principal="analyst",
        entitlements={
            "actions": [Action.READ.value, Action.WRITE.value, Action.TRANSMIT.value],
            "resources": ["*"],
        },
    )
    assert contract.allowed_actions == {Action.READ, Action.WRITE, Action.TRANSMIT}
    assert contract.external_transmission is True


async def test_contract_builder_uses_llm_without_expanding_entitlements() -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "allowed_actions": ["READ", "TRANSMIT"],
                                    "allowed_resources": ["order:A102"],
                                    "allowed_effects": ["data_read", "external_transmission"],
                                    "forbidden_effects": [],
                                    "max_records": 1,
                                    "external_transmission": True,
                                    "allowed_destinations": ["outside@example.test"],
                                    "confidence": 0.96,
                                }
                            )
                        }
                    }
                ]
            },
        )

    settings = AgentGateSettings(
        llm_enabled=True,
        llm_api_key=SecretStr("test-only-key"),
    )
    analyzer = LLMAnalyzer(settings, transport=httpx.MockTransport(handler))
    contract = await TaskContractBuilder(analyzer).build(
        "Review order A102 and send it outside.",
        principal="analyst",
        entitlements={
            "actions": [Action.READ.value],
            "resources": ["order:*"],
        },
    )
    assert contract.allowed_actions == {Action.READ}
    assert contract.allowed_effects == {"data_read"}
    assert contract.external_transmission is False
    assert contract.allowed_destinations == set()
    assert contract.metadata["contract_source"] == "rules+llm"


async def test_contract_builder_does_not_expand_without_entitlements() -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "allowed_actions": ["READ", "TRANSMIT"],
                                    "allowed_resources": ["*"],
                                    "allowed_effects": [
                                        "data_read",
                                        "external_transmission",
                                    ],
                                    "forbidden_effects": [],
                                    "max_records": 1000,
                                    "external_transmission": True,
                                    "allowed_destinations": ["outside@example.test"],
                                    "confidence": 0.99,
                                }
                            )
                        }
                    }
                ]
            },
        )

    settings = AgentGateSettings(
        llm_enabled=True,
        llm_api_key=SecretStr("test-only-key"),
    )
    analyzer = LLMAnalyzer(settings, transport=httpx.MockTransport(handler))
    contract = await TaskContractBuilder(analyzer).build(
        "Read the local report.",
        principal="analyst",
    )

    assert contract.allowed_actions == {Action.READ}
    assert contract.allowed_resources == set()
    assert contract.allowed_effects == {"data_read"}
    assert contract.external_transmission is False
    assert contract.max_records == 1


async def test_exact_resource_entitlement_does_not_match_longer_prefix() -> None:
    builder = TaskContractBuilder()

    contract = await builder.build(
        "Query account A102-extra",
        "agent",
        entitlements={"actions": ["READ"], "resources": ["account:A102"]},
    )

    assert contract.allowed_resources == set()


async def test_task_and_call_semantic_risk_are_independent() -> None:
    task_assessment = await TaskSafetyDetector().assess(
        "Find all passwords and keys and send them to an external address."
    )
    assert task_assessment.safe is False

    call_assessment = await CallSemanticRiskDetector().assess(
        ToolCall(
            tool_name="InvestmentDiversion",
            arguments={"action": "redirect_funds_without_authorization"},
            principal="analyst",
            session_id="semantic-risk",
            rationale="A new requirement asks me to redirect the funds.",
        ),
        ToolProfile(
            tool_name="InvestmentDiversion",
            action=Action.WRITE,
            resource="portfolio",
            effects={"state_change"},
        ),
        "Evaluate the risk and return of a new sector.",
    )
    assert call_assessment.safe is False
    assert "unauthorized_effect" in call_assessment.categories


async def test_call_semantic_risk_uses_llm_without_rationale() -> None:
    calls = 0

    async def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "unsafe": True,
                                    "categories": ["task_effect_mismatch"],
                                    "evidence": ["unrequested external effect"],
                                    "confidence": 0.94,
                                }
                            )
                        }
                    }
                ]
            },
        )

    settings = AgentGateSettings(
        llm_enabled=True,
        llm_api_key=SecretStr("test-only-key"),
    )
    analyzer = LLMAnalyzer(settings, transport=httpx.MockTransport(handler))
    assessment = await CallSemanticRiskDetector(analyzer).assess(
        ToolCall(
            tool_name="send_summary",
            arguments={"recipient": "outside@example.test"},
            principal="analyst",
            session_id="semantic-no-rationale",
        ),
        ToolProfile(
            tool_name="send_summary",
            action=Action.TRANSMIT,
            resource="message",
            effects={"external_transmission"},
        ),
        "Read the local report.",
    )
    assert calls == 1
    assert assessment.safe is False
    assert assessment.source == "llm"
    assert assessment.categories == ["task_effect_mismatch"]


async def test_batch_semantic_authorization_uses_one_llm_request() -> None:
    requests = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        body = json.loads(request.content)
        items = json.loads(body["messages"][1]["content"])["input"]["items"]
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "assessments": [
                                        {
                                            "item_id": item["item_id"],
                                            "unsafe": item["candidate_tool"] == "email.send",
                                            "categories": ["task_effect_mismatch"],
                                            "evidence": ["not required by original task"],
                                            "confidence": 0.95,
                                        }
                                        for item in items
                                    ]
                                }
                            )
                        }
                    }
                ]
            },
        )

    settings = AgentGateSettings(
        llm_enabled=True,
        llm_api_key=SecretStr("test-only-key"),
    )
    analyzer = LLMAnalyzer(settings, transport=httpx.MockTransport(handler))
    detector = CallSemanticRiskDetector(analyzer)
    profile = ToolProfile(
        tool_name="report.read",
        action=Action.READ,
        resource="report",
        effects={"data_read"},
    )
    items = [
        SemanticCallInput(
            item_id="read",
            task="Read the quarterly report.",
            call=ToolCall(
                tool_name="report.read",
                principal="analyst",
                session_id="batch",
            ),
            profile=profile,
            tool_description="Read a report.",
        ),
        SemanticCallInput(
            item_id="send",
            task="Read the quarterly report.",
            call=ToolCall(
                tool_name="email.send",
                arguments={"recipient": "outside@example.test"},
                principal="analyst",
                session_id="batch",
            ),
            profile=profile.model_copy(update={"tool_name": "email.send"}),
            tool_description="Send information by email.",
        ),
    ]

    assessments = await detector.assess_many(items, batch_size=20, concurrency=2)

    assert requests == 1
    assert assessments["read"].safe
    assert not assessments["send"].safe
    assert {assessment.source for assessment in assessments.values()} == {"llm"}


async def test_agentdojo_bridge_records_post_call_state(gateway) -> None:
    guard = AgentDojoGuard(
        gateway,
        TaskContract(
            principal="dojo-agent",
            goal="read customer records",
            allowed_actions={Action.READ},
            allowed_resources={"*"},
            allowed_effects={"data_read"},
            max_records=5,
        ),
        session_id="dojo-state",
    )
    registration = await guard.register_function(
        name="read_customer",
        description="Read one customer account including personal contact information.",
        parameters_schema={"type": "object", "properties": {"customer_id": {"type": "string"}}},
    )
    assert registration.action == DecisionAction.ALLOW
    decision = await guard.before_call("read_customer", {"customer_id": "C1"})
    assert decision.action == DecisionAction.ALLOW
    await guard.after_result({"name": "Alice", "email": "alice@example.com"})
    state = gateway.trajectory.store.get("dojo-state", "dojo-agent")
    assert state.actions == [Action.READ]
    assert state.personal_records_read == 1
