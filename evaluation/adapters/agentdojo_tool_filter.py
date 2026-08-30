from __future__ import annotations

import os

from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLMToolFilter

_ORIGINAL_INIT = OpenAILLMToolFilter.__init__


def _compatible_init(self, prompt, client, model, temperature=0.0):
    override = os.getenv("AGENTDOJO_TOOL_FILTER_MODEL_ID")
    if model == "openai-compatible" and override:
        model = override
    _ORIGINAL_INIT(self, prompt, client, model, temperature)


OpenAILLMToolFilter.__init__ = _compatible_init
