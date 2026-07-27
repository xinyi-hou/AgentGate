from __future__ import annotations

from agentgate.models import Action, Sensitivity
from agentgate.tools.backend import MockBackend
from agentgate.tools.common import definition
from agentgate.tools.registry import ToolDefinition


def network_tools(backend: MockBackend) -> list[ToolDefinition]:
    async def fetch_url(args: dict) -> dict:
        event = {"kind": "fetch", "url": str(args["url"])}
        backend.network_events.append(event)
        return {"url": event["url"], "content": f"mock content from {event['url']}"}

    async def download_url(args: dict) -> dict:
        event = {"kind": "download", "url": str(args["url"])}
        backend.network_events.append(event)
        return {"url": event["url"], "content": "downloaded mock document"}

    async def post_webhook(args: dict) -> dict:
        event = {"kind": "webhook", "url": str(args["url"]), "payload": args["payload"]}
        backend.network_events.append(event)
        return {"delivered": True, "url": event["url"]}

    async def upload_cloud(args: dict) -> dict:
        event = {
            "kind": "cloud_upload",
            "destination": str(args["destination"]),
            "content": args["content"],
        }
        backend.uploads.append(event)
        return {"uploaded": True, "url": f"https://files.example.test/{len(backend.uploads)}"}

    async def resolve_url(args: dict) -> dict:
        url = str(args["url"])
        host = url.split("/", 3)[2] if "://" in url else url
        return {"url": url, "host": host, "is_external": not host.endswith(".internal")}

    return [
        definition(
            name="network.fetch_url",
            description="Fetch text from a URL through the controlled network fixture.",
            action=Action.READ,
            resource="network",
            handler=fetch_url,
            properties={"url": {"type": "string"}},
            required=["url"],
            output_sensitivity={Sensitivity.INTERNAL},
        ),
        definition(
            name="network.download_url",
            description="Download one document from a URL through the controlled fixture.",
            action=Action.READ,
            resource="network",
            handler=download_url,
            properties={"url": {"type": "string"}},
            required=["url"],
        ),
        definition(
            name="network.post_webhook",
            description="Transmit a payload to an external webhook URL.",
            action=Action.TRANSMIT,
            resource="network",
            handler=post_webhook,
            properties={"url": {"type": "string"}, "payload": {}},
            required=["url", "payload"],
            destination="external",
        ),
        definition(
            name="network.upload_cloud",
            description="Upload content to an external cloud destination.",
            action=Action.TRANSMIT,
            resource="network",
            handler=upload_cloud,
            properties={"destination": {"type": "string"}, "content": {}},
            required=["destination", "content"],
            destination="external",
        ),
        definition(
            name="network.resolve_url",
            description="Resolve a URL into a normalized host and trust boundary.",
            action=Action.READ,
            resource="network",
            handler=resolve_url,
            properties={"url": {"type": "string"}},
            required=["url"],
            requires_confirmation=False,
        ),
    ]
