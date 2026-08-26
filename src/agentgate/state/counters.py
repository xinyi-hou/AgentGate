from __future__ import annotations

from agentgate.events.models import (
    DataType,
    EffectType,
    SecurityOperation,
    ToolSecurityEvent,
    TrustDomain,
)

SENSITIVE_TYPES = {
    DataType.INTERNAL,
    DataType.PERSONAL,
    DataType.FINANCIAL,
    DataType.CREDENTIAL,
    DataType.SECRET,
}


def counter_delta(event: ToolSecurityEvent) -> dict[str, int]:
    if event.success is False:
        return {"failed_call_count": 1}
    affected = max(0, event.affected_count or 0)
    delta: dict[str, int] = {}
    if event.operation == SecurityOperation.READ:
        records = affected or 1
        delta["records_read"] = records
        if event.data_types & SENSITIVE_TYPES:
            delta["sensitive_records_read"] = records
        if DataType.PERSONAL in event.data_types:
            delta["personal_records_read"] = records
    if event.operation == SecurityOperation.SEND and event.trust_domain in {
        TrustDomain.TRUSTED_EXTERNAL,
        TrustDomain.UNKNOWN_EXTERNAL,
    }:
        delta["external_send_count"] = 1
    if event.operation == SecurityOperation.EXECUTE:
        delta["execute_count"] = 1
    if EffectType.PRIVILEGED in event.effects:
        delta["privileged_action_count"] = 1
    if event.operation == SecurityOperation.DELETE:
        delta["delete_count"] = 1
    if event.operation == SecurityOperation.INSTALL:
        delta["install_count"] = 1
    return delta
