from __future__ import annotations

from pathlib import Path

from evaluation.runners.build_mcp_threat_subsets import (
    build_mcp_bench,
    build_mcp_safety,
    build_msb,
    build_subsets,
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


def test_mcp_primary_matrix_has_paired_safety_and_utility_controls(tmp_path: Path) -> None:
    build_subsets(repository_root=".", output_root=tmp_path)
    manifest = (tmp_path / "manifests/mcp_threat_model_subset.jsonl").read_text(
        encoding="utf-8"
    )

    assert manifest.count('"benchmark": "MCP-SafetyBench"') == 148
    assert manifest.count('"label": "positive"') == 74
    assert manifest.count('"label": "negative"') == 74
    assert manifest.count('"benchmark": "MCP-Bench"') == 48
