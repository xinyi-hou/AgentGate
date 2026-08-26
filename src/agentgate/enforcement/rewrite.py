from __future__ import annotations

from typing import Any


def apply_restriction(
    original: dict[str, Any],
    rewritten: dict[str, Any] | None,
) -> dict[str, Any]:
    if rewritten is None:
        raise ValueError("RESTRICT decision requires rewritten arguments")
    if set(rewritten) != set(original):
        raise ValueError("restriction cannot add or remove top-level arguments")
    for key, new_value in rewritten.items():
        if not _is_narrower(original[key], new_value):
            raise ValueError(f"restriction expands argument: {key}")
    return rewritten


def _is_narrower(original: Any, rewritten: Any) -> bool:
    if isinstance(original, bool) or isinstance(rewritten, bool):
        return original == rewritten
    if isinstance(original, (int, float)) and isinstance(rewritten, (int, float)):
        return rewritten <= original
    if isinstance(original, str) and isinstance(rewritten, str):
        return original == rewritten
    if isinstance(original, list) and isinstance(rewritten, list):
        return len(rewritten) <= len(original) and all(item in original for item in rewritten)
    if isinstance(original, dict) and isinstance(rewritten, dict):
        return set(rewritten).issubset(original) and all(
            _is_narrower(original[key], value) for key, value in rewritten.items()
        )
    return original == rewritten
