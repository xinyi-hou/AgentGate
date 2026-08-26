from __future__ import annotations

from agentgate.capabilities.models import ToolCapability
from agentgate.events.models import DataType, EventPhase, ToolExecutionResult, ToolSecurityEvent
from agentgate.state.provenance import infer_output_types


class ResultClassifier:
    def classify(
        self,
        request: ToolSecurityEvent,
        execution: ToolExecutionResult,
        capability: ToolCapability,
    ) -> ToolSecurityEvent:
        data_types = set(request.data_types)
        if execution.success:
            data_types.update(capability.sensitive_output_types)
            data_types.update(infer_output_types(execution.output))
            if not data_types:
                data_types.add(DataType.PUBLIC)
        affected_count = execution.affected_count
        if affected_count is None:
            affected_count = len(execution.output) if isinstance(execution.output, list) else 1
        return request.model_copy(
            deep=True,
            update={
                "phase": EventPhase.RESULT,
                "data_types": data_types,
                "sensitivity": set(data_types),
                "result": execution.output,
                "success": execution.success,
                "affected_count": affected_count,
                "untrusted_context": request.untrusted_context or capability.untrusted_output,
                "timestamp": execution.timestamp,
            },
        )
