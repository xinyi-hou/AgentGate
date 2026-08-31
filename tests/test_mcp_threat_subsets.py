from __future__ import annotations

from pathlib import Path

from evaluation.runners.build_mcp_threat_subsets import (
    build_mcp_bench,
    build_mcp_safety,
    build_msb,
)


def test_mcp_threat_model_manifests_cover_pinned_sources() -> None:
    repository_root = Path(".").resolve()
    mcp_safety = build_mcp_safety(repository_root)
    msb = build_msb(repository_root)
    mcp_bench = build_mcp_bench(repository_root)

    assert len(mcp_safety) == 245
    assert len(msb) == 60
    assert len(mcp_bench) == 104
    assert sum(row["selected"] for row in mcp_bench) == 48
    for row in mcp_safety + msb + mcp_bench:
        if row["applicability"] == "core":
            assert row["observable_at_tool_boundary"]
            assert row["mediated_by_mcp_proxy"]
            assert row["pre_effect_enforceable"]
            assert row["representable_by_agentgate"]
