from __future__ import annotations

from agentgate.models import Action, Sensitivity
from agentgate.tools.backend import MockBackend
from agentgate.tools.common import definition
from agentgate.tools.registry import ToolDefinition


def filesystem_tools(backend: MockBackend) -> list[ToolDefinition]:
    async def read_file(args: dict) -> dict:
        path = str(args["path"])
        if path not in backend.files:
            raise FileNotFoundError(path)
        return {"path": path, "content": backend.files[path]}

    async def write_file(args: dict) -> dict:
        path = str(args["path"])
        backend.files[path] = str(args["content"])
        return {"path": path, "written": True}

    async def delete_file(args: dict) -> dict:
        path = str(args["path"])
        existed = path in backend.files
        backend.files.pop(path, None)
        return {"path": path, "deleted": existed}

    async def search_files(args: dict) -> list[dict]:
        query = str(args["query"]).lower()
        limit = int(args.get("limit", 10))
        return [
            {"path": path, "snippet": content[:120]}
            for path, content in backend.files.items()
            if query in path.lower() or query in content.lower()
        ][:limit]

    async def list_files(args: dict) -> list[str]:
        prefix = str(args.get("prefix", "/workspace"))
        limit = int(args.get("limit", 20))
        return [path for path in sorted(backend.files) if path.startswith(prefix)][:limit]

    return [
        definition(
            name="filesystem.read_file",
            description="Read one file from the controlled workspace.",
            action=Action.READ,
            resource="filesystem",
            handler=read_file,
            properties={"path": {"type": "string"}},
            required=["path"],
            output_sensitivity={Sensitivity.INTERNAL},
        ),
        definition(
            name="filesystem.write_file",
            description="Write text to one file in the controlled workspace.",
            action=Action.WRITE,
            resource="filesystem",
            handler=write_file,
            properties={"path": {"type": "string"}, "content": {"type": "string"}},
            required=["path", "content"],
        ),
        definition(
            name="filesystem.delete_file",
            description="Delete one file from the controlled workspace.",
            action=Action.DELETE,
            resource="filesystem",
            handler=delete_file,
            properties={"path": {"type": "string"}},
            required=["path"],
        ),
        definition(
            name="filesystem.search_files",
            description="Search file names and contents with a bounded result limit.",
            action=Action.READ,
            resource="filesystem",
            handler=search_files,
            properties={"query": {"type": "string"}, "limit": {"type": "integer"}},
            required=["query"],
            scope="bounded",
            output_sensitivity={Sensitivity.INTERNAL},
        ),
        definition(
            name="filesystem.list_files",
            description="List files below one path prefix.",
            action=Action.READ,
            resource="filesystem",
            handler=list_files,
            properties={"prefix": {"type": "string"}, "limit": {"type": "integer"}},
            scope="bounded",
        ),
    ]
