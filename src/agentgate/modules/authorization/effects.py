from __future__ import annotations

from typing import Any

from agentgate.models import Action, CallEffect, ToolCall, ToolProfile


class EffectInferer:
    def infer(self, profile: ToolProfile, call: ToolCall) -> CallEffect:
        args = call.arguments
        resource = _resource_from_args(profile.resource, args)
        record_count = _record_count(profile.scope, args)
        scope = "bulk" if record_count > 20 or _is_wildcard(args) else profile.scope
        destination = _destination(profile, args)
        effects = set(profile.effects)
        if profile.destination == "external" or destination.startswith(("http://", "https://")):
            effects.add("external_transmission")
        if scope == "bulk" and profile.action == Action.READ:
            effects.add("data_export")
        data_access = set(args.get("fields", [])) if isinstance(args.get("fields"), list) else set()
        return CallEffect(
            action=profile.action,
            resource=resource,
            scope=scope,
            record_count=record_count,
            data_access=data_access,
            effects=effects,
            destination=destination,
            reversible=profile.action not in {Action.DELETE, Action.EXECUTE, Action.TRANSMIT},
        )


def _resource_from_args(resource_type: str, args: dict[str, Any]) -> str:
    for key in ("order_id", "account_id", "customer_id", "service", "path", "resource_id"):
        if value := args.get(key):
            kind = key.removesuffix("_id")
            return f"{kind}:{value}"
    if _is_wildcard(args):
        return f"{resource_type}:*"
    return resource_type


def _destination(profile: ToolProfile, args: dict[str, Any]) -> str:
    if profile.destination == "internal":
        return "internal"
    if profile.action != Action.TRANSMIT:
        return profile.destination
    return str(
        args.get("destination")
        or args.get("recipient")
        or args.get("url")
        or profile.destination
    )


def _record_count(default_scope: str, args: dict[str, Any]) -> int:
    for key in ("limit", "count", "max_records"):
        value = args.get(key)
        if isinstance(value, int) and value >= 0:
            return value
    return 1000 if default_scope == "bulk" or _is_wildcard(args) else 1


def _is_wildcard(args: dict[str, Any]) -> bool:
    values = {str(value).strip().lower() for value in args.values() if not isinstance(value, list)}
    return bool(values & {"*", "all", "all_records", "everything"})
