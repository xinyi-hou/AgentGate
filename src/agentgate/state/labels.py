from __future__ import annotations

from agentgate.events.models import (
    DataType,
    EffectType,
    SecurityOperation,
    ToolSecurityEvent,
    TrustDomain,
)
from agentgate.state.models import StateLabel


def labels_for_event(event: ToolSecurityEvent) -> set[StateLabel]:
    labels: set[StateLabel] = set()
    mapping = {
        DataType.PERSONAL: StateLabel.HAS_PERSONAL_DATA,
        DataType.FINANCIAL: StateLabel.HAS_FINANCIAL_DATA,
        DataType.CREDENTIAL: StateLabel.HAS_CREDENTIAL,
        DataType.SECRET: StateLabel.HAS_SECRET,
    }
    labels.update(mapping[data_type] for data_type in event.data_types if data_type in mapping)
    if event.untrusted_context or (
        event.operation == SecurityOperation.READ
        and event.trust_domain == TrustDomain.UNKNOWN_EXTERNAL
    ):
        labels.add(StateLabel.EXPOSED_TO_UNTRUSTED_CONTENT)
    if event.operation == SecurityOperation.SEND and event.trust_domain in {
        TrustDomain.TRUSTED_EXTERNAL,
        TrustDomain.UNKNOWN_EXTERNAL,
    }:
        labels.add(StateLabel.USED_EXTERNAL_COMMUNICATION)
    if EffectType.PRIVILEGED in event.effects:
        labels.add(StateLabel.USED_PRIVILEGED_OPERATION)
    if EffectType.DESTRUCTIVE in event.effects:
        labels.add(StateLabel.USED_DESTRUCTIVE_OPERATION)
    return labels
