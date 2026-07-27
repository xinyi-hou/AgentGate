from __future__ import annotations

import json

import httpx
from pydantic import SecretStr

from agentgate.config import AgentGateSettings
from agentgate.llm import LLMAnalyzer
from agentgate.models import Action, CallEffect, Sensitivity, ToolCall, ToolProfile, ToolResult
from agentgate.modules.trajectory import SemanticSensitivityClassifier, TrajectoryModule


async def test_semantic_sensitivity_labels_extend_rule_labels() -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "labels": ["Restricted"],
                                    "confidence": 0.93,
                                    "evidence": ["internal legal investigation"],
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
    classifier = SemanticSensitivityClassifier(analyzer)
    assessment = await classifier.classify(
        {"case": "confidential investigation summary"},
        ToolProfile(
            tool_name="legal.lookup",
            action=Action.READ,
            resource="case",
        ),
        {Sensitivity.INTERNAL},
    )
    assert assessment.labels == {Sensitivity.INTERNAL, Sensitivity.RESTRICTED}
    assert assessment.source == "rules+llm"

    trajectory = TrajectoryModule(settings, sensitivity_classifier=classifier)
    result = await trajectory.observe_result(
        ToolCall(
            tool_name="legal.lookup",
            principal="analyst",
            session_id="semantic-label-state",
        ),
        CallEffect(action=Action.READ, resource="case:1"),
        ToolProfile(
            tool_name="legal.lookup",
            action=Action.READ,
            resource="case",
        ),
        ToolResult(
            call_id="semantic-result",
            tool_name="legal.lookup",
            output={"case": "confidential investigation summary"},
        ),
    )
    assert result.security_metadata["sensitivity"]["source"] == "rules+llm"
    state = trajectory.store.get("semantic-label-state", "analyst")
    call_node = next(node for node in state.nodes.values() if node.kind == "call")
    assert call_node.attributes["sensitivity_source"] == "rules+llm"
