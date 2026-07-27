from __future__ import annotations

from agentgate.tools import build_default_registry


async def test_controlled_tool_environment_has_five_domains_and_26_tools() -> None:
    registry, backend = build_default_registry()
    assert len(registry) == 26
    domains = {spec.name.split(".", 1)[0] for spec in registry.specs()}
    assert domains == {"filesystem", "database", "network", "messaging", "business"}
    before = backend.snapshot()
    await registry.get("filesystem.write_file").handler(
        {"path": "/workspace/new.txt", "content": "hello"}
    )
    after = backend.snapshot()
    assert before != after
    assert after["files"]["/workspace/new.txt"] == "hello"
