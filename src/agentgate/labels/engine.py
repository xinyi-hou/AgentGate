from __future__ import annotations

from agentgate.events import (
    DataType,
    ResourceType,
    SecurityOperation,
    ToolSecurityEvent,
    TrustDomain,
)
from agentgate.graph.models import DataObjectNode
from agentgate.labels.models import SecurityLabel

_DATA_LABELS = {
    DataType.INTERNAL: SecurityLabel.INTERNAL_DATA,
    DataType.PERSONAL: SecurityLabel.PERSONAL,
    DataType.FINANCIAL: SecurityLabel.FINANCIAL,
    DataType.CREDENTIAL: SecurityLabel.CREDENTIAL,
    DataType.SECRET: SecurityLabel.SECRET,
}

_PROPAGATABLE_LABELS = {
    SecurityLabel.SENSITIVE,
    SecurityLabel.CREDENTIAL,
    SecurityLabel.SECRET,
    SecurityLabel.PERSONAL,
    SecurityLabel.FINANCIAL,
    SecurityLabel.INTERNAL_DATA,
    SecurityLabel.UNTRUSTED,
    SecurityLabel.EXTERNAL_ORIGIN,
    SecurityLabel.SUSPICIOUS_CONTROL_CONTENT,
}


def initial_data_labels(event: ToolSecurityEvent, data_types: set[DataType]) -> set[SecurityLabel]:
    labels = {label for data_type, label in _DATA_LABELS.items() if data_type in data_types}
    if data_types - {DataType.PUBLIC}:
        labels.add(SecurityLabel.SENSITIVE)
    if event.operation == SecurityOperation.READ:
        labels.add(SecurityLabel.TOOL_PROVIDED)
        if event.untrusted_context or event.trust_domain == TrustDomain.UNKNOWN_EXTERNAL:
            labels.update({SecurityLabel.UNTRUSTED, SecurityLabel.EXTERNAL_ORIGIN})
        elif event.trust_domain in {TrustDomain.LOCAL, TrustDomain.INTERNAL}:
            labels.update({SecurityLabel.TRUSTED, SecurityLabel.INTERNAL_ORIGIN})
    if event.operation == SecurityOperation.WRITE:
        labels.add(SecurityLabel.PERSISTENT_ARTIFACT)
        if event.resource_type == ResourceType.CONFIG:
            labels.add(SecurityLabel.CONFIGURATION)
    if any(
        item.startswith("content_finding:") and item.rsplit(":", 1)[-1] in {"HIGH", "CRITICAL"}
        for item in event.trust_evidence
    ):
        labels.update({SecurityLabel.UNTRUSTED, SecurityLabel.SUSPICIOUS_CONTROL_CONTENT})
    return labels


def propagate_data_labels(
    node: DataObjectNode,
    parents: list[DataObjectNode],
) -> DataObjectNode:
    inherited = {
        label for parent in parents for label in parent.labels if label in _PROPAGATABLE_LABELS
    }
    return node.model_copy(update={"labels": set(node.labels) | inherited})
