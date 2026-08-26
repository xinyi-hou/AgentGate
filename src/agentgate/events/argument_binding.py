from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from agentgate.capabilities.models import ToolCapability
from agentgate.events.models import (
    DataType,
    EffectType,
    RawToolCall,
    SecurityOperation,
    TrustDomain,
)
from agentgate.events.operation_classifier import get_argument
from agentgate.state.models import SensitiveObject
from agentgate.state.provenance import match_sensitive_objects


@dataclass(frozen=True)
class BoundArguments:
    resource_id: str | None
    scope: dict[str, Any] | None
    object_ids: list[str]
    data_types: set[DataType]
    destination: str | None
    destination_type: str | None
    trust_domain: TrustDomain
    effects: set[EffectType]


class ArgumentBinder:
    def __init__(
        self,
        *,
        internal_domains: set[str] | None = None,
        trusted_external_domains: set[str] | None = None,
    ):
        self.internal_domains = {item.lower() for item in (internal_domains or set())}
        self.trusted_external_domains = {
            item.lower() for item in (trusted_external_domains or set())
        }

    def bind(
        self,
        call: RawToolCall,
        capability: ToolCapability,
        operation: SecurityOperation,
        sensitive_objects: Iterable[SensitiveObject],
    ) -> BoundArguments:
        resource = get_argument(call.arguments, capability.resource_arg)
        destination_value = get_argument(call.arguments, capability.destination_arg)
        destination = str(destination_value) if destination_value is not None else None
        matched = match_sensitive_objects(call.arguments, sensitive_objects)
        data_types = set(capability.sensitive_input_types)
        if operation == SecurityOperation.READ:
            data_types.update(capability.sensitive_output_types)
        data_types.update(item.data_type for item in matched)
        trust_domain, destination_type = self.classify_destination(destination)
        effects = set(capability.default_effects) | operation_effects(operation)
        if operation == SecurityOperation.SEND and trust_domain in {
            TrustDomain.TRUSTED_EXTERNAL,
            TrustDomain.UNKNOWN_EXTERNAL,
        }:
            effects.add(EffectType.EXTERNAL)
        return BoundArguments(
            resource_id=str(resource) if resource is not None else None,
            scope=bind_scope(call.arguments, capability.scope_arg),
            object_ids=[item.object_id for item in matched],
            data_types=data_types,
            destination=destination,
            destination_type=destination_type,
            trust_domain=trust_domain,
            effects=effects,
        )

    def classify_destination(
        self,
        destination: str | None,
    ) -> tuple[TrustDomain, str | None]:
        if destination is None:
            return TrustDomain.LOCAL, None
        rendered = destination.strip()
        host = destination_host(rendered)
        destination_type = classify_destination_type(rendered)
        lowered = host.lower()
        if lowered in {"localhost", "127.0.0.1", "::1"}:
            return TrustDomain.LOCAL, destination_type
        if matches_domain(lowered, self.internal_domains) or lowered.endswith(
            (".internal", ".local")
        ):
            return TrustDomain.INTERNAL, destination_type
        if matches_domain(lowered, self.trusted_external_domains):
            return TrustDomain.TRUSTED_EXTERNAL, destination_type
        return TrustDomain.UNKNOWN_EXTERNAL, destination_type


def bind_scope(arguments: dict[str, Any], scope_arg: str | None) -> dict[str, Any] | None:
    value = get_argument(arguments, scope_arg)
    if value is None:
        return None
    try:
        count = max(0, int(value))
    except (TypeError, ValueError):
        return {"argument": scope_arg, "value": str(value)}
    return {"argument": scope_arg, "count": count}


def destination_host(destination: str) -> str:
    if "@" in destination and "://" not in destination:
        return destination.rsplit("@", 1)[-1]
    parsed = urlparse(destination if "://" in destination else f"//{destination}")
    return parsed.hostname or destination.split("/", 1)[0]


def classify_destination_type(destination: str) -> str:
    if "@" in destination and "://" not in destination:
        return "EMAIL_ADDRESS"
    if destination.startswith(("http://", "https://")):
        return "HTTP_ENDPOINT"
    if destination.startswith(("/", "./", "../")):
        return "FILE_PATH"
    return "IDENTIFIER"


def matches_domain(host: str, configured: set[str]) -> bool:
    return any(host == domain or host.endswith(f".{domain}") for domain in configured)


def operation_effects(operation: SecurityOperation) -> set[EffectType]:
    return {
        SecurityOperation.WRITE: {EffectType.PERSISTENT},
        SecurityOperation.EXECUTE: {EffectType.PRIVILEGED},
        SecurityOperation.DELETE: {
            EffectType.PERSISTENT,
            EffectType.DESTRUCTIVE,
            EffectType.IRREVERSIBLE,
        },
        SecurityOperation.AUTH: {EffectType.PRIVILEGED},
        SecurityOperation.INSTALL: {EffectType.PERSISTENT, EffectType.PRIVILEGED},
    }.get(operation, set())
