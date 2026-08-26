from fastapi import Request

from agentgate.runtime.gateway import AgentGateRuntime


def get_runtime(request: Request) -> AgentGateRuntime:
    return request.app.state.agentgate
