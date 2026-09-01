from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from time import perf_counter
from typing import Any, Protocol

from agentgate.capabilities.models import InferredField, OutputTrust, ToolCapability
from agentgate.events.models import DataType, EffectType, ResourceType, SecurityOperation
from agentgate.semantics.models import SemanticResolution, SemanticResolver


class CapabilityFactExtractor(Protocol):
    async def __call__(
        self,
        *,
        name: str,
        description: str,
        input_schema: dict[str, Any],
        output_schema: dict[str, Any],
    ) -> ToolCapability | None: ...


FactExtractorCallable = Callable[..., Awaitable[ToolCapability | None]]


_OPERATION_WORDS: tuple[tuple[SecurityOperation, tuple[str, ...]], ...] = (
    (
        SecurityOperation.DELETE,
        (
            "delete",
            "remove",
            "destroy",
            "drop",
            "deactivate",
            "disable",
            "revoke",
            "terminate",
            "clear",
            "purge",
        ),
    ),
    (
        SecurityOperation.PRIVILEGE,
        (
            "grant_role",
            "grant role",
            "chmod",
            "chown",
            "iam_policy",
            "administrator",
            "manage_collaborator",
            "manage collaborator",
            "grant_access",
            "grant access",
            "access_rights",
            "access rights",
            "permission",
            "privilege",
        ),
    ),
    (
        SecurityOperation.AUTH,
        (
            "auth",
            "login",
            "token",
            "credential",
            "authenticate",
            "unlock",
            "password",
            "verify_identity",
            "verify identity",
        ),
    ),
    (SecurityOperation.INSTALL, ("install", "deploy", "enable_plugin", "register_skill")),
    (
        SecurityOperation.EXECUTE,
        (
            "execute",
            "shell",
            "command",
            "run",
            "restart",
            "shutdown",
            "reboot",
            "poweroff",
            "spawn",
            "launch",
        ),
    ),
    (
        SecurityOperation.SEND,
        (
            "send",
            "share",
            "forward",
            "transfer",
            "upload",
            "post",
            "publish",
            "webhook",
            "email",
            "contact",
            "withdraw",
            "wire",
            "remit",
        ),
    ),
    (
        SecurityOperation.TRANSFORM,
        ("transform", "convert", "encode", "decode", "summarize", "translate"),
    ),
    (
        SecurityOperation.WRITE,
        (
            "write",
            "update",
            "create",
            "save",
            "put",
            "configure",
            "book",
            "reserve",
            "schedule",
            "change",
            "refund",
            "cancel",
            "add",
            "append",
            "reschedule",
            "adjust",
            "invite",
            "set",
            "click",
            "confirm",
            "decline",
            "perform",
            "handle",
        ),
    ),
    (
        SecurityOperation.READ,
        ("read", "get", "query", "search", "list", "fetch", "download", "predict", "generate"),
    ),
    (SecurityOperation.DELEGATE, ("delegate", "handoff", "assign_agent", "assign agent")),
)

_PRIMARY_ACTION_WORDS: dict[str, SecurityOperation] = {
    word: operation
    for operation, words in _OPERATION_WORDS
    for word in words
    if "_" not in word and " " not in word
}

_RESOURCE_WORDS: tuple[tuple[ResourceType, tuple[str, ...]], ...] = (
    (ResourceType.CREDENTIAL, ("credential", "token", "secret", "password", "api_key")),
    (ResourceType.FILE, ("file", "path", "directory", "folder")),
    (ResourceType.DATABASE, ("database", "table", "query", "record", "row")),
    (ResourceType.MESSAGE, ("message", "email", "mail", "notification")),
    (ResourceType.PROCESS, ("process", "shell", "command", "script")),
    (ResourceType.NETWORK, ("url", "http", "webhook", "network", "download", "upload")),
    (ResourceType.CONFIG, ("config", "setting", "preference")),
    (ResourceType.APPLICATION, ("application", "service", "plugin", "skill", "package")),
)


class CapabilityInferer:
    def __init__(
        self,
        semantic_extractor: CapabilityFactExtractor | None = None,
        *,
        semantic_resolver: SemanticResolver | None = None,
        llm_confidence_threshold: float = 0.75,
    ):
        self.semantic_extractor = semantic_extractor
        self.semantic_resolver = semantic_resolver
        self.llm_confidence_threshold = llm_confidence_threshold

    async def infer(
        self,
        *,
        name: str,
        description: str = "",
        input_schema: dict[str, Any] | None = None,
        output_schema: dict[str, Any] | None = None,
        annotations: dict[str, Any] | None = None,
    ) -> ToolCapability:
        schema = input_schema or {}
        output = output_schema or {}
        text = f"{name} {description} {' '.join(_schema_fields(schema))}".lower()
        primary = _primary_operation(name, description)
        candidates = (
            [primary]
            if primary is not None
            else [
                operation
                for operation, words in _OPERATION_WORDS
                if any(_contains_semantic_term(text, word) for word in words)
            ]
        )
        candidates = list(dict.fromkeys(candidates))
        resolution_reason = _resolution_reason(name, text, candidates)
        if resolution_reason is not None and self.semantic_resolver is not None:
            started = perf_counter()
            resolved = await self.semantic_resolver.resolve(
                name=name,
                description=description,
                input_schema=schema,
                output_schema=output,
                candidates=candidates,
                reason=resolution_reason,
            )
            latency_ms = (perf_counter() - started) * 1000
            if resolved is not None:
                try:
                    return _capability_from_resolution(
                        name=name,
                        description=description,
                        input_schema=schema,
                        output_schema=output,
                        annotations=annotations or {},
                        resolution=resolved,
                        reason=resolution_reason,
                        latency_ms=latency_ms,
                        threshold=self.llm_confidence_threshold,
                    )
                except ValueError:
                    # Preserve the call as UNKNOWN instead of inventing READ semantics.
                    pass

        operation = candidates[0] if len(candidates) == 1 else None
        if operation is None and self.semantic_extractor is not None:
            extracted = await self.semantic_extractor(
                name=name,
                description=description,
                input_schema=schema,
                output_schema=output,
            )
            if extracted is not None:
                return extracted.model_copy(update={"source": "semantic_extractor"})
        if operation is None:
            return _unknown_capability(
                name=name,
                description=description,
                input_schema=schema,
                output_schema=output,
                annotations=annotations or {},
                reason=resolution_reason or "no_deterministic_operation",
            )

        resource_type = next(
            (
                kind
                for kind, words in _RESOURCE_WORDS
                if any(_contains_semantic_term(text, word) for word in words)
            ),
            ResourceType.UNKNOWN,
        )
        fields = _schema_fields(schema)
        output_fields = _schema_fields(output)
        confidence = 0.85 if resource_type != ResourceType.UNKNOWN else 0.7
        if resolution_reason is not None and operation in {
            SecurityOperation.EXECUTE,
            SecurityOperation.DELETE,
            SecurityOperation.AUTH,
            SecurityOperation.PRIVILEGE,
            SecurityOperation.INSTALL,
        }:
            confidence = min(confidence, 0.55)
        evidence = [
            f"operation_keyword:{operation.value}",
            f"resource_keyword:{resource_type.value}",
            *[f"schema_field:{field}" for field in fields],
            *[f"output_schema_field:{field}" for field in output_fields],
        ]
        resource_arg = _first_field(
            fields,
            (
                "path",
                "file_id",
                "event_id",
                "account_id",
                "table",
                "resource",
                "channel",
                "account",
                "id",
                "name",
                "service",
            ),
        )
        scope_arg = _first_field(fields, ("limit", "count", "max_records"))
        destination_arg = None
        financial_semantics = any(
            token in text
            for token in (
                "money",
                "transaction",
                "payment",
                "iban",
                "wallet",
                "withdraw",
                "balance",
                "price",
                "financial",
            )
        )
        if operation == SecurityOperation.SEND:
            destination_arg = _first_field(
                fields,
                (
                    "destination",
                    "recipient",
                    "receiver",
                    "receive_name",
                    "recipient_name",
                    "to",
                    "target",
                    "address",
                    "url",
                    "endpoint",
                    "channel",
                    "account",
                ),
            )
        elif operation == SecurityOperation.WRITE and financial_semantics:
            destination_arg = _first_field(
                fields,
                ("recipient", "receiver", "to", "target", "account", "iban", "wallet"),
            )
        elif operation == SecurityOperation.READ and resource_type == ResourceType.NETWORK:
            destination_arg = _first_field(fields, ("url", "endpoint", "host"))
        payload_args = [
            field
            for field in fields
            if any(
                word in field.lower()
                for word in (
                    "body",
                    "content",
                    "payload",
                    "data",
                    "attachment",
                    "file",
                    "path",
                    "document",
                )
            )
        ]
        input_fields = [
            field for field in fields if destination_arg is None or field != destination_arg
        ]
        input_types = _sensitive_types(input_fields)
        input_types.update(_declared_payload_types(text, operation))
        output_types = _sensitive_types(output_fields)
        effects = _effects_for(operation)
        declared_effects = _declared_high_impact_effects(text)
        effects.update(declared_effects)
        evidence.extend(
            f"declared_effect:{effect.value}" for effect in sorted(declared_effects, key=str)
        )
        if operation == SecurityOperation.WRITE and financial_semantics and destination_arg:
            effects.add(EffectType.EXTERNAL)
        inferred_fields = {
            name: InferredField(
                value=value,
                confidence=confidence,
                evidence=evidence,
                source="heuristic" if name in {"operation", "resource_type"} else "schema",
            )
            for name, value in {
                "operation": operation.value,
                "resource_type": resource_type.value,
                "resource_arg": resource_arg,
                "scope_arg": scope_arg,
                "destination_arg": destination_arg,
                "payload_args": payload_args,
                "sensitive_input_types": sorted(item.value for item in input_types),
                "sensitive_output_types": sorted(item.value for item in output_types),
                "effects": sorted(item.value for item in effects),
            }.items()
        }
        return ToolCapability(
            tool_name=name,
            possible_operations=[operation],
            resource_type=resource_type,
            resource_arg=resource_arg,
            scope_arg=scope_arg,
            destination_arg=destination_arg,
            payload_args=payload_args,
            sensitive_input_types=input_types,
            sensitive_output_types=output_types,
            default_effects=effects,
            description=description,
            input_schema=schema,
            output_schema=output,
            annotations=annotations or {},
            source="schema_inference",
            confidence=confidence,
            evidence=evidence,
            inferred_fields=inferred_fields,
            output_trust=(
                OutputTrust.DYNAMIC
                if operation == SecurityOperation.READ and resource_type == ResourceType.NETWORK
                else OutputTrust.INTERNAL
            ),
            resolution_metadata={
                "resolver_called": False,
                "resolver_reason": resolution_reason,
                "source": "deterministic",
            },
        )


def _resolution_reason(
    name: str,
    text: str,
    candidates: list[SecurityOperation],
) -> str | None:
    if not candidates:
        return "no_deterministic_operation"
    if len(candidates) > 1:
        return "multiple_operation_candidates"
    generic_names = {"sync_workspace", "process_record", "run_action", "prepare", "handle"}
    if name.lower() in generic_names:
        return "generic_tool_semantics"
    if (
        candidates[0] == SecurityOperation.EXECUTE
        and "run" in text
        and not any(token in text for token in ("command", "shell", "script", "process", "execute"))
    ):
        return "weak_execute_keyword"
    return None


def _primary_operation(name: str, description: str) -> SecurityOperation | None:
    """Prefer the declared action verb over nouns and secondary effects in a tool schema."""
    name_tokens = re.findall(r"[a-z0-9]+", re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name).lower())
    token_set = set(name_tokens)
    if token_set & {"shutdown", "reboot", "poweroff", "restart"}:
        return SecurityOperation.EXECUTE
    if token_set & {"password", "credential", "token"} and token_set & {
        "change",
        "reset",
        "set",
        "update",
        "verify",
    }:
        return SecurityOperation.AUTH
    if token_set & {"access", "permission", "privilege", "role", "collaborator"} and token_set & {
        "add",
        "change",
        "grant",
        "manage",
        "modify",
        "remove",
        "revoke",
        "set",
        "update",
    }:
        return SecurityOperation.PRIVILEGE
    if token_set & {"delete", "deletion", "remove"} and "confirm" in token_set:
        return SecurityOperation.DELETE
    if "collaborator" in token_set and token_set & {"manage", "add", "remove"}:
        return SecurityOperation.PRIVILEGE
    if name_tokens:
        operation = _action_for_token(name_tokens[0])
        if operation is not None:
            return operation
        name_operations = {
            operation
            for token in name_tokens
            if (operation := _action_for_token(token)) is not None
        }
        if len(name_operations) == 1:
            return next(iter(name_operations))

    first_sentence = re.split(r"[.\n]", description.strip(), maxsplit=1)[0].lower()
    description_operations = {
        operation
        for operation, words in _OPERATION_WORDS
        if any(_contains_semantic_term(first_sentence, word) for word in words)
    }
    if len(description_operations) == 1:
        return next(iter(description_operations))
    return None


def _action_for_token(token: str) -> SecurityOperation | None:
    for candidate in (token, token.removesuffix("s"), token.removesuffix("es")):
        if operation := _PRIMARY_ACTION_WORDS.get(candidate):
            return operation
    return None


def _contains_semantic_term(text: str, term: str) -> bool:
    parts = [re.escape(item) for item in re.split(r"[ _-]+", term) if item]
    if not parts:
        return False
    pattern = r"(?<![a-z0-9])" + r"[ _-]+".join(parts) + r"(?![a-z0-9])"
    return bool(re.search(pattern, text, re.IGNORECASE))


def _capability_from_resolution(
    *,
    name: str,
    description: str,
    input_schema: dict[str, Any],
    output_schema: dict[str, Any],
    annotations: dict[str, Any],
    resolution: SemanticResolution,
    reason: str,
    latency_ms: float,
    threshold: float,
) -> ToolCapability:
    if resolution.operation is None or resolution.confidence < threshold:
        raise ValueError(
            f"semantic resolver confidence is insufficient for {name!r}; "
            "register an explicit capability"
        )
    evidence = ["semantic_resolver", *resolution.evidence]
    fields = {
        "operation": resolution.operation.value,
        "resource_type": (resolution.resource_type or ResourceType.UNKNOWN).value,
        "resource_arg": resolution.resource_arg,
        "scope_arg": resolution.scope_arg,
        "destination_arg": resolution.destination_arg,
        "payload_args": resolution.payload_args,
        "sensitive_input_types": sorted(item.value for item in resolution.input_data_types),
        "sensitive_output_types": sorted(item.value for item in resolution.output_data_types),
        "effects": sorted(item.value for item in resolution.effects),
    }
    return ToolCapability(
        tool_name=name,
        possible_operations=[resolution.operation],
        resource_type=resolution.resource_type or ResourceType.UNKNOWN,
        resource_arg=resolution.resource_arg,
        scope_arg=resolution.scope_arg,
        destination_arg=resolution.destination_arg,
        payload_args=resolution.payload_args,
        sensitive_input_types=resolution.input_data_types,
        sensitive_output_types=resolution.output_data_types,
        default_effects=resolution.effects,
        description=description,
        input_schema=input_schema,
        output_schema=output_schema,
        annotations=annotations,
        source="semantic_resolver",
        confidence=resolution.confidence,
        evidence=evidence,
        inferred_fields={
            field: InferredField(
                value=value,
                confidence=resolution.confidence,
                evidence=evidence,
                source="semantic_resolver",
            )
            for field, value in fields.items()
        },
        output_trust=(
            OutputTrust.DYNAMIC
            if resolution.operation == SecurityOperation.READ
            and resolution.resource_type == ResourceType.NETWORK
            else OutputTrust.INTERNAL
        ),
        resolution_metadata={
            "resolver_called": True,
            "resolver_reason": reason,
            "resolver_latency_ms": latency_ms,
            "source": "semantic_resolver",
        },
    )


def _schema_fields(schema: dict[str, Any]) -> list[str]:
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        return []
    fields: list[str] = []
    for field, definition in properties.items():
        fields.append(str(field))
        if isinstance(definition, dict):
            fields.extend(f"{field}.{child}" for child in _schema_fields(definition))
            items = definition.get("items")
            if isinstance(items, dict):
                fields.extend(f"{field}.{child}" for child in _schema_fields(items))
    return fields


def _sensitive_types(fields: list[str]) -> set[DataType]:
    mapping = {
        DataType.CREDENTIAL: ("token", "credential", "password", "api_key", "private_key"),
        DataType.SECRET: ("secret", "classified", "confidential"),
        DataType.PERSONAL: ("email", "phone", "address", "customer", "recipient", "name"),
        DataType.FINANCIAL: (
            "amount",
            "price",
            "payment",
            "card",
            "iban",
            "wallet",
            "balance",
            "financial",
        ),
        DataType.INTERNAL: (
            "internal",
            "private",
            "config",
            "system",
            "dataset",
            "server log",
            "audit log",
        ),
    }
    lowered = " ".join(fields).lower()
    return {
        data_type for data_type, words in mapping.items() if any(word in lowered for word in words)
    }


def _first_field(fields: list[str], candidates: tuple[str, ...]) -> str | None:
    return next(
        (field for candidate in candidates for field in fields if _field_matches(field, candidate)),
        None,
    )


def _field_matches(field: str, candidate: str) -> bool:
    leaf = field.rsplit(".", 1)[-1].lower()
    singular = leaf.removesuffix("s")
    return (
        leaf == candidate
        or singular == candidate
        or leaf.startswith(f"{candidate}_")
        or leaf.endswith(f"_{candidate}")
    )


def _declared_high_impact_effects(text: str) -> set[EffectType]:
    effects: set[EffectType] = set()
    if re.search(
        r"\b(?:must|required|needs?)\s+(?:to\s+)?be\s+approved\b|"
        r"\bonly\s+(?:be\s+)?used\s+by\b.{0,40}\b(?:admin|root|administrator)\b",
        text,
        re.IGNORECASE,
    ):
        effects.add(EffectType.PRIVILEGED)
    if re.search(
        r"\b(?:data corruption|irreversible|permanent damage|destructive)\b",
        text,
        re.IGNORECASE,
    ):
        effects.update({EffectType.DESTRUCTIVE, EffectType.IRREVERSIBLE})
    return effects


def _declared_payload_types(
    text: str,
    operation: SecurityOperation,
) -> set[DataType]:
    if operation not in {
        SecurityOperation.SEND,
        SecurityOperation.WRITE,
        SecurityOperation.AUTH,
    }:
        return set()
    mapping = {
        DataType.CREDENTIAL: ("credential", "password", "api key", "private key", "token"),
        DataType.SECRET: ("secret", "classified", "confidential"),
        DataType.PERSONAL: ("patient data", "health data", "genetic data", "customer data"),
        DataType.FINANCIAL: ("money", "balance", "payment", "price", "iban", "wallet"),
        DataType.INTERNAL: (
            "server log",
            "audit log",
            "log data",
            "dataset",
            "system config",
            "configuration",
        ),
    }
    return {
        data_type
        for data_type, phrases in mapping.items()
        if any(phrase in text for phrase in phrases)
    }


def _effects_for(operation: SecurityOperation) -> set[EffectType]:
    return {
        SecurityOperation.WRITE: {EffectType.PERSISTENT},
        SecurityOperation.SEND: {EffectType.EXTERNAL},
        SecurityOperation.EXECUTE: {EffectType.PRIVILEGED},
        SecurityOperation.DELETE: {
            EffectType.PERSISTENT,
            EffectType.DESTRUCTIVE,
            EffectType.IRREVERSIBLE,
        },
        SecurityOperation.AUTH: {EffectType.PRIVILEGED},
        SecurityOperation.PRIVILEGE: {EffectType.PRIVILEGED},
        SecurityOperation.INSTALL: {EffectType.PERSISTENT, EffectType.PRIVILEGED},
        SecurityOperation.DELEGATE: {EffectType.PRIVILEGED},
    }.get(operation, set())


def _unknown_capability(
    *,
    name: str,
    description: str,
    input_schema: dict[str, Any],
    output_schema: dict[str, Any],
    annotations: dict[str, Any],
    reason: str,
) -> ToolCapability:
    evidence = [f"unknown_semantics:{reason}"]
    return ToolCapability(
        tool_name=name,
        possible_operations=[SecurityOperation.UNKNOWN],
        resource_type=ResourceType.UNKNOWN,
        description=description,
        input_schema=input_schema,
        output_schema=output_schema,
        annotations=annotations,
        source="conservative_unknown",
        confidence=0.25,
        evidence=evidence,
        inferred_fields={
            "operation": InferredField(
                value=SecurityOperation.UNKNOWN.value,
                confidence=0.25,
                evidence=evidence,
                source="conservative_unknown",
            )
        },
        output_trust=OutputTrust.DYNAMIC,
        resolution_metadata={
            "resolver_called": False,
            "resolver_reason": reason,
            "source": "conservative_unknown",
        },
    )
