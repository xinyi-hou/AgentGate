from __future__ import annotations

from agentgate.models import CallEffect, TaskContract, ToolCall


def least_privilege_rewrite(
    call: ToolCall, effect: CallEffect, contract: TaskContract
) -> dict[str, object] | None:
    rewritten = dict(call.arguments)
    changed = False
    if effect.record_count > contract.max_records and "limit" in rewritten:
        rewritten["limit"] = contract.max_records
        changed = True

    allowed = sorted(
        resource for resource in contract.allowed_resources if not resource.endswith(":*")
    )
    if effect.resource.endswith(":*") and len(allowed) == 1:
        kind, value = allowed[0].split(":", 1)
        field = {
            "order": "order_id",
            "account": "account_id",
            "customer": "customer_id",
            "service": "service",
        }.get(kind)
        if field:
            rewritten[field] = value
            for wildcard_field in ("filter", "scope", "resource_id"):
                if rewritten.get(wildcard_field) in {"*", "all", "all_records"}:
                    rewritten.pop(wildcard_field)
            changed = True

    return rewritten if changed else None
