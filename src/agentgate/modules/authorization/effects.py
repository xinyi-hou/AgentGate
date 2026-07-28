from __future__ import annotations

import ipaddress
import posixpath
import re
from collections.abc import Iterator
from typing import Any
from urllib.parse import unquote, urlsplit, urlunsplit

from agentgate.models import Action, CallEffect, ToolCall, ToolProfile

COUNT_FIELDS = {"limit", "count", "max_records", "page_size", "batch_size", "top", "n"}
DESTINATION_FIELDS = {
    "destination",
    "recipient",
    "recipients",
    "url",
    "uri",
    "endpoint",
    "webhook",
    "webhook_url",
    "target_url",
}
SQL_FIELDS = {"sql", "query", "statement"}
COMMAND_FIELDS = {"command", "cmd", "shell", "script", "code"}
PATH_FIELDS = {"path", "file", "filename", "directory", "prefix"}
RESOURCE_ID_FIELDS = {
    "order_id",
    "account_id",
    "customer_id",
    "resource_id",
    "service",
    "tenant_id",
    "project_id",
    "document_id",
    "record_id",
}
FIELD_SELECTION_FIELDS = {"fields", "columns", "select", "projection"}

SQL_ACTIONS = {
    "select": Action.READ,
    "show": Action.READ,
    "describe": Action.READ,
    "explain": Action.READ,
    "insert": Action.WRITE,
    "update": Action.WRITE,
    "merge": Action.WRITE,
    "replace": Action.WRITE,
    "delete": Action.DELETE,
    "drop": Action.DELETE,
    "truncate": Action.DELETE,
    "alter": Action.CONFIGURE,
    "create": Action.CONFIGURE,
    "grant": Action.CONFIGURE,
    "revoke": Action.CONFIGURE,
}

EXPLICIT_ACTIONS = {
    "read": Action.READ,
    "get": Action.READ,
    "list": Action.READ,
    "search": Action.READ,
    "write": Action.WRITE,
    "update": Action.WRITE,
    "create": Action.WRITE,
    "refund": Action.WRITE,
    "pay": Action.WRITE,
    "transfer": Action.WRITE,
    "reallocate": Action.WRITE,
    "redirect": Action.WRITE,
    "delete": Action.DELETE,
    "remove": Action.DELETE,
    "drop": Action.DELETE,
    "execute": Action.EXECUTE,
    "run": Action.EXECUTE,
    "restart": Action.EXECUTE,
    "send": Action.TRANSMIT,
    "email": Action.TRANSMIT,
    "upload": Action.TRANSMIT,
    "post": Action.TRANSMIT,
    "configure": Action.CONFIGURE,
    "grant": Action.CONFIGURE,
    "revoke": Action.CONFIGURE,
}


class EffectInferer:
    def infer(self, profile: ToolProfile, call: ToolCall) -> CallEffect:
        args = call.arguments
        action = _action_from_arguments(profile.action, args)
        resource = _resource_from_args(profile.resource, args)
        record_count = _record_count(profile.scope, args)
        scope = "bulk" if record_count > 20 or _is_wildcard(args) else profile.scope
        destination = _destination(profile, action, args)
        effects = _effects(profile, action, args, destination, scope)
        data_access = _data_access(args)
        return CallEffect(
            action=action,
            resource=resource,
            scope=scope,
            record_count=record_count,
            data_access=data_access,
            effects=effects,
            destination=destination,
            reversible=action not in {Action.DELETE, Action.EXECUTE, Action.TRANSMIT},
        )


def _action_from_arguments(default: Action, args: dict[str, Any]) -> Action:
    fields = {_field_name(path) for path, _ in _walk(args)}
    if fields & {"amount", "price", "payment", "currency"} and fields & {
        "recipient",
        "account_id",
        "client_account_id",
        "iban",
        "wallet",
    }:
        return Action.WRITE
    for path, value in _walk(args):
        field = _field_name(path)
        if field in SQL_FIELDS and isinstance(value, str):
            if sql_action := _sql_action(value):
                return sql_action
        if field in COMMAND_FIELDS and isinstance(value, str) and value.strip():
            return Action.EXECUTE
        if field in {"action", "operation", "method", "mode"} and isinstance(value, str):
            normalized = re.sub(r"[^a-z]+", " ", value.lower())
            for token in normalized.split():
                if token in EXPLICIT_ACTIONS:
                    return EXPLICIT_ACTIONS[token]
    return default


def _resource_from_args(resource_type: str, args: dict[str, Any]) -> str:
    for path, value in _walk(args):
        field = _field_name(path)
        if value is None or isinstance(value, (dict, list, tuple, set)):
            continue
        if field in PATH_FIELDS:
            return f"path:{_normalize_path(str(value))}"
        if field in RESOURCE_ID_FIELDS or field.endswith("_id"):
            kind = field.removesuffix("_id")
            if kind == "resource":
                kind = resource_type
            return f"{kind}:{value}"
        if field in SQL_FIELDS and isinstance(value, str):
            if table := _sql_resource(value):
                return f"{resource_type}:{table}"
    if _is_wildcard(args):
        return f"{resource_type}:*"
    return resource_type


def _destination(profile: ToolProfile, action: Action, args: dict[str, Any]) -> str:
    if profile.destination == "internal":
        return "internal"
    candidates: list[str] = []
    for path, value in _walk(args):
        if _field_name(path) not in DESTINATION_FIELDS:
            continue
        if isinstance(value, (str, int, float)):
            candidates.append(str(value))
    if not candidates:
        return profile.destination
    destination = candidates[0]
    if action == Action.TRANSMIT:
        return _normalize_destination(destination)
    return profile.destination


def _record_count(default_scope: str, args: dict[str, Any]) -> int:
    counts: list[int] = []
    for path, value in _walk(args):
        field = _field_name(path)
        if field in COUNT_FIELDS and isinstance(value, int) and value >= 0:
            counts.append(value)
        if field in SQL_FIELDS and isinstance(value, str):
            if limit := re.search(r"\blimit\s+(\d+)\b", value, flags=re.I):
                counts.append(int(limit.group(1)))
            elif _sql_action(value) == Action.READ:
                counts.append(1000)
    if counts:
        return max(counts)
    return 100 if default_scope == "bulk" or _is_wildcard(args) else 1


def _is_wildcard(args: dict[str, Any]) -> bool:
    for path, value in _walk(args):
        field = _field_name(path)
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"*", "all", "all_records", "everything"}:
                return True
            if field in SQL_FIELDS and re.search(r"\bselect\s+\*\b", normalized):
                return True
    return False


def _effects(
    profile: ToolProfile,
    action: Action,
    args: dict[str, Any],
    destination: str,
    scope: str,
) -> set[str]:
    effects = set(profile.effects)
    effects.update(
        {
            Action.READ: {"data_read"},
            Action.WRITE: {"state_change"},
            Action.DELETE: {"state_change", "destructive"},
            Action.EXECUTE: {"state_change", "code_execution"},
            Action.TRANSMIT: set(),
            Action.CONFIGURE: {"state_change"},
        }.get(action, set())
    )
    if action == Action.TRANSMIT and destination != "internal":
        effects.add("external_transmission")
    if _contains_path_escape(args):
        effects.add("path_escape")
    if _contains_private_network_target(args):
        effects.add("internal_network_access")
    fields = {_field_name(path) for path, _ in _walk(args)}
    if fields & {"token", "secret", "password", "credential", "api_key", "private_key"}:
        effects.add("credential_access")
    if fields & {"amount", "price", "payment", "currency"} and fields & {
        "recipient",
        "account_id",
        "client_account_id",
        "iban",
        "wallet",
    }:
        effects.add("financial_transaction")
        effects.add("state_change")
    return effects


def _data_access(args: dict[str, Any]) -> set[str]:
    fields: set[str] = set()
    for path, value in _walk(args):
        if _field_name(path) not in FIELD_SELECTION_FIELDS:
            continue
        if isinstance(value, str):
            fields.update(part.strip() for part in value.split(",") if part.strip())
        elif isinstance(value, (list, tuple, set)):
            fields.update(str(part).strip() for part in value if str(part).strip())
    return fields


def _walk(value: Any, path: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], Any]]:
    if isinstance(value, dict):
        for key, nested in value.items():
            yield from _walk(nested, (*path, str(key)))
    elif isinstance(value, (list, tuple, set)):
        for index, nested in enumerate(value):
            yield from _walk(nested, (*path, str(index)))
    elif path:
        yield path, value


def _field_name(path: tuple[str, ...]) -> str:
    for component in reversed(path):
        if not component.isdigit():
            return component.lower()
    return path[-1].lower()


def _sql_action(statement: str) -> Action | None:
    normalized = re.sub(r"/\*.*?\*/|--[^\n]*", " ", statement, flags=re.S).strip().lower()
    if normalized.startswith("with "):
        matches = re.findall(
            r"\b(select|insert|update|merge|replace|delete|drop|truncate|alter|create|grant|revoke)\b",
            normalized,
        )
        return SQL_ACTIONS.get(matches[-1]) if matches else None
    operation = normalized.split(None, 1)[0] if normalized else ""
    return SQL_ACTIONS.get(operation)


def _sql_resource(statement: str) -> str | None:
    match = re.search(
        r"\b(?:from|join|update|into|table)\s+([A-Za-z_][A-Za-z0-9_.-]*)",
        statement,
        flags=re.I,
    )
    return match.group(1).lower() if match else None


def _normalize_path(value: str) -> str:
    decoded = unquote(value.strip())
    normalized = posixpath.normpath(decoded)
    if decoded.startswith("/") and not normalized.startswith("/"):
        normalized = f"/{normalized}"
    return normalized


def _contains_path_escape(args: dict[str, Any]) -> bool:
    return any(
        _field_name(path) in PATH_FIELDS
        and isinstance(value, str)
        and ".." in unquote(value).replace("\\", "/").split("/")
        for path, value in _walk(args)
    )


def _normalize_destination(value: str) -> str:
    stripped = value.strip()
    try:
        parsed = urlsplit(stripped)
        port = f":{parsed.port}" if parsed.port else ""
    except ValueError:
        return stripped
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return stripped.lower() if "@" in stripped else stripped
    hostname = parsed.hostname.lower().rstrip(".")
    return urlunsplit(
        (parsed.scheme.lower(), f"{hostname}{port}", parsed.path or "", parsed.query, "")
    )


def _contains_private_network_target(args: dict[str, Any]) -> bool:
    for path, value in _walk(args):
        if _field_name(path) not in DESTINATION_FIELDS or not isinstance(value, str):
            continue
        try:
            hostname = urlsplit(value).hostname
        except ValueError:
            continue
        if not hostname:
            continue
        if hostname in {"localhost", "metadata.google.internal"} or hostname.endswith(".internal"):
            return True
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            continue
        if address.is_private or address.is_loopback or address.is_link_local:
            return True
    return False
