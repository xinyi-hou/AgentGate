from __future__ import annotations

from agentgate.models import Action
from agentgate.tools.backend import MockBackend
from agentgate.tools.common import definition
from agentgate.tools.registry import ToolDefinition


def messaging_tools(backend: MockBackend) -> list[ToolDefinition]:
    async def send_email(args: dict) -> dict:
        event = {"kind": "email", **args}
        backend.messages.append(event)
        return {"sent": True, "message_id": f"email-{len(backend.messages)}"}

    async def send_message(args: dict) -> dict:
        event = {"kind": "message", **args}
        backend.messages.append(event)
        return {"sent": True, "message_id": f"msg-{len(backend.messages)}"}

    async def upload_attachment(args: dict) -> dict:
        event = {"kind": "attachment", **args}
        backend.uploads.append(event)
        return {"attachment_id": f"att-{len(backend.uploads)}"}

    async def create_share_link(args: dict) -> dict:
        event = {"kind": "share", **args}
        backend.uploads.append(event)
        return {"url": f"https://share.example.test/{len(backend.uploads)}"}

    async def notify_user(args: dict) -> dict:
        event = {"kind": "notification", **args}
        backend.messages.append(event)
        return {"notified": True}

    return [
        definition(
            name="messaging.send_email",
            description="Send an email to one recipient.",
            action=Action.TRANSMIT,
            resource="message",
            handler=send_email,
            properties={
                "recipient": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
                "attachment": {},
            },
            required=["recipient", "subject", "body"],
            destination="external",
        ),
        definition(
            name="messaging.send_message",
            description="Send a message to an external channel or user.",
            action=Action.TRANSMIT,
            resource="message",
            handler=send_message,
            properties={"recipient": {"type": "string"}, "body": {"type": "string"}},
            required=["recipient", "body"],
            destination="external",
        ),
        definition(
            name="messaging.upload_attachment",
            description="Upload an attachment for later message delivery.",
            action=Action.TRANSMIT,
            resource="message",
            handler=upload_attachment,
            properties={"destination": {"type": "string"}, "content": {}},
            required=["destination", "content"],
            destination="external",
        ),
        definition(
            name="messaging.create_share_link",
            description="Create an externally accessible link for stored content.",
            action=Action.TRANSMIT,
            resource="message",
            handler=create_share_link,
            properties={"resource_id": {"type": "string"}, "destination": {"type": "string"}},
            required=["resource_id", "destination"],
            destination="external",
        ),
        definition(
            name="messaging.notify_user",
            description="Send a bounded notification to a named application user.",
            action=Action.TRANSMIT,
            resource="message",
            handler=notify_user,
            properties={"recipient": {"type": "string"}, "body": {"type": "string"}},
            required=["recipient", "body"],
            effects={"internal_notification"},
            destination="internal",
        ),
    ]
