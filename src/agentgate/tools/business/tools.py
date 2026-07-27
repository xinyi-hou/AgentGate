from __future__ import annotations

from agentgate.models import Action, Sensitivity
from agentgate.tools.backend import MockBackend
from agentgate.tools.common import definition
from agentgate.tools.registry import ToolDefinition


def business_tools(backend: MockBackend) -> list[ToolDefinition]:
    async def get_order(args: dict) -> dict:
        return dict(backend.orders[str(args["order_id"])])

    async def refund_order(args: dict) -> dict:
        order_id = str(args["order_id"])
        amount = float(args["amount"])
        event = {"kind": "refund", "order_id": order_id, "amount": amount}
        backend.business_events.append(event)
        return {"refunded": True, **event}

    async def get_account(args: dict) -> dict:
        return dict(backend.accounts[str(args["account_id"])])

    async def update_account(args: dict) -> dict:
        account_id = str(args["account_id"])
        backend.accounts[account_id].update(dict(args["updates"]))
        return dict(backend.accounts[account_id])

    async def restart_service(args: dict) -> dict:
        service = str(args["service"])
        backend.services[service] = "restarted"
        event = {"kind": "restart", "service": service}
        backend.business_events.append(event)
        return {"restarted": True, "service": service}

    async def issue_api_token(args: dict) -> dict:
        account_id = str(args["account_id"])
        token = f"issued_{account_id}_{len(backend.business_events) + 1}"
        event = {"kind": "issue_token", "account_id": account_id}
        backend.business_events.append(event)
        return {"account_id": account_id, "token": token}

    return [
        definition(
            name="business.get_order",
            description="Read one business order by exact order ID.",
            action=Action.READ,
            resource="orders",
            handler=get_order,
            properties={"order_id": {"type": "string"}},
            required=["order_id"],
            output_sensitivity={Sensitivity.PERSONAL, Sensitivity.FINANCIAL},
        ),
        definition(
            name="business.refund_order",
            description="Refund a specified amount for one order.",
            action=Action.WRITE,
            resource="orders",
            handler=refund_order,
            properties={"order_id": {"type": "string"}, "amount": {"type": "number"}},
            required=["order_id", "amount"],
            effects={"state_change", "financial_transaction"},
        ),
        definition(
            name="business.get_account",
            description="Read one account by exact account ID.",
            action=Action.READ,
            resource="customers",
            handler=get_account,
            properties={"account_id": {"type": "string"}},
            required=["account_id"],
            output_sensitivity={Sensitivity.PERSONAL},
        ),
        definition(
            name="business.update_account",
            description="Update fields on one customer account.",
            action=Action.WRITE,
            resource="customers",
            handler=update_account,
            properties={"account_id": {"type": "string"}, "updates": {"type": "object"}},
            required=["account_id", "updates"],
        ),
        definition(
            name="business.restart_service",
            description="Restart one named service in the controlled environment.",
            action=Action.EXECUTE,
            resource="service",
            handler=restart_service,
            properties={"service": {"type": "string"}},
            required=["service"],
        ),
        definition(
            name="business.issue_api_token",
            description="Issue a new API token for one account.",
            action=Action.WRITE,
            resource="credentials",
            handler=issue_api_token,
            properties={"account_id": {"type": "string"}},
            required=["account_id"],
            effects={"state_change", "credential_creation"},
            output_sensitivity={Sensitivity.CREDENTIAL},
        ),
    ]
