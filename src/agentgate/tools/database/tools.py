from __future__ import annotations

from agentgate.models import Action, Sensitivity
from agentgate.tools.backend import MockBackend
from agentgate.tools.common import definition
from agentgate.tools.registry import ToolDefinition


def database_tools(backend: MockBackend) -> list[ToolDefinition]:
    async def query_orders(args: dict) -> list[dict]:
        order_id = args.get("order_id")
        limit = int(args.get("limit", 1))
        fields = args.get("fields")
        records = (
            [backend.orders[str(order_id)]]
            if order_id and str(order_id) in backend.orders
            else list(backend.orders.values())
        )[:limit]
        if fields:
            return [{key: row.get(key) for key in fields} for row in records]
        return [dict(row) for row in records]

    async def update_order(args: dict) -> dict:
        order_id = str(args["order_id"])
        backend.orders[order_id].update(dict(args["updates"]))
        return dict(backend.orders[order_id])

    async def export_orders(args: dict) -> list[dict]:
        limit = int(args.get("limit", len(backend.orders)))
        return [dict(row) for row in list(backend.orders.values())[:limit]]

    async def query_customers(args: dict) -> list[dict]:
        customer_id = args.get("customer_id")
        limit = int(args.get("limit", 1))
        records = (
            [backend.customers[str(customer_id)]]
            if customer_id and str(customer_id) in backend.customers
            else list(backend.customers.values())
        )[:limit]
        return [dict(row) for row in records]

    async def query_credentials(args: dict) -> dict:
        name = str(args["name"])
        return {"name": name, "credential": backend.credentials[name]}

    return [
        definition(
            name="database.query_orders",
            description="Query order records with an optional exact order ID and bounded limit.",
            action=Action.READ,
            resource="orders",
            handler=query_orders,
            properties={
                "order_id": {"type": "string"},
                "limit": {"type": "integer"},
                "fields": {"type": "array", "items": {"type": "string"}},
            },
            scope="bounded",
            output_sensitivity={Sensitivity.PERSONAL, Sensitivity.FINANCIAL},
        ),
        definition(
            name="database.update_order",
            description="Update fields on one order record.",
            action=Action.WRITE,
            resource="orders",
            handler=update_order,
            properties={"order_id": {"type": "string"}, "updates": {"type": "object"}},
            required=["order_id", "updates"],
        ),
        definition(
            name="database.export_orders",
            description="Export a bulk collection of order records.",
            action=Action.READ,
            resource="orders",
            handler=export_orders,
            properties={"limit": {"type": "integer"}, "destination": {"type": "string"}},
            effects={"data_read", "data_export"},
            scope="bulk",
            output_sensitivity={Sensitivity.PERSONAL, Sensitivity.FINANCIAL},
        ),
        definition(
            name="database.query_customers",
            description="Query customer contact records by exact ID or bounded limit.",
            action=Action.READ,
            resource="customers",
            handler=query_customers,
            properties={"customer_id": {"type": "string"}, "limit": {"type": "integer"}},
            scope="bounded",
            output_sensitivity={Sensitivity.PERSONAL},
        ),
        definition(
            name="database.query_credentials",
            description="Read one protected service credential by name.",
            action=Action.READ,
            resource="credentials",
            handler=query_credentials,
            properties={"name": {"type": "string"}},
            required=["name"],
            effects={"data_read", "credential_access"},
            output_sensitivity={Sensitivity.CREDENTIAL},
            requires_confirmation=True,
        ),
    ]
