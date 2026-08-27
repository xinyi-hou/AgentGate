from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Protocol

from agentgate.capabilities.models import ToolCapability
from agentgate.events.models import DataType, EffectType, ResourceType, SecurityOperation


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
    (SecurityOperation.DELETE, ("delete", "remove", "destroy", "drop")),
    (SecurityOperation.AUTH, ("auth", "login", "token", "credential", "permission", "role")),
    (SecurityOperation.INSTALL, ("install", "deploy", "enable_plugin", "register_skill")),
    (SecurityOperation.EXECUTE, ("execute", "shell", "command", "run", "restart", "spawn")),
    (SecurityOperation.SEND, ("send", "upload", "post", "publish", "webhook", "email")),
    (SecurityOperation.WRITE, ("write", "update", "create", "save", "put", "configure")),
    (SecurityOperation.READ, ("read", "get", "query", "search", "list", "fetch", "download")),
)

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
    def __init__(self, semantic_extractor: CapabilityFactExtractor | None = None):
        self.semantic_extractor = semantic_extractor

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
        operation = next(
            (
                operation
                for operation, words in _OPERATION_WORDS
                if any(word in text for word in words)
            ),
            None,
        )
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
            raise ValueError(
                f"cannot infer a security operation for {name!r}; register an explicit capability"
            )

        resource_type = next(
            (kind for kind, words in _RESOURCE_WORDS if any(word in text for word in words)),
            ResourceType.UNKNOWN,
        )
        fields = _schema_fields(schema)
        output_fields = _schema_fields(output)
        return ToolCapability(
            tool_name=name,
            possible_operations=[operation],
            resource_type=resource_type,
            resource_arg=_first_field(
                fields, ("path", "table", "resource", "id", "name", "service")
            ),
            scope_arg=_first_field(fields, ("limit", "count", "max_records")),
            destination_arg=_first_field(
                fields, ("destination", "recipient", "url", "endpoint", "channel")
            ),
            payload_args=[
                field
                for field in fields
                if any(word in field.lower() for word in ("body", "content", "payload", "data"))
            ],
            sensitive_input_types=_sensitive_types(fields),
            sensitive_output_types=_sensitive_types(output_fields),
            default_effects=_effects_for(operation),
            description=description,
            input_schema=schema,
            output_schema=output,
            annotations=annotations or {},
            source="schema_inference",
            confidence=0.85 if resource_type != ResourceType.UNKNOWN else 0.7,
            evidence=[
                f"operation_keyword:{operation.value}",
                f"resource_keyword:{resource_type.value}",
                *[f"schema_field:{field}" for field in fields],
                *[f"output_schema_field:{field}" for field in output_fields],
            ],
            untrusted_output=(
                operation == SecurityOperation.READ and resource_type == ResourceType.NETWORK
            ),
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
        DataType.FINANCIAL: ("amount", "price", "payment", "card", "iban", "wallet"),
        DataType.INTERNAL: ("internal", "private"),
    }
    lowered = " ".join(fields).lower()
    return {
        data_type
        for data_type, words in mapping.items()
        if any(word in lowered for word in words)
    }


def _first_field(fields: list[str], candidates: tuple[str, ...]) -> str | None:
    return next(
        (field for candidate in candidates for field in fields if candidate in field.lower()),
        None,
    )


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
        SecurityOperation.INSTALL: {EffectType.PERSISTENT, EffectType.PRIVILEGED},
    }.get(operation, set())
