from __future__ import annotations

import hashlib
import json

from agentgate.models import ToolFingerprint, ToolProfile, ToolSpec


def fingerprint_tool(spec: ToolSpec, profile: ToolProfile) -> ToolFingerprint:
    structural = {
        "name": spec.name,
        "namespace": spec.namespace,
        "source": spec.source,
        "publisher": spec.publisher,
        "version": spec.version,
        "input_schema": spec.input_schema,
        "output_schema": spec.output_schema,
        "dependencies": sorted(spec.dependencies),
    }
    semantic_tokens = tuple(
        sorted(
            {
                profile.action.value,
                profile.resource,
                profile.scope,
                profile.destination,
                *profile.effects,
                *(label.value for label in profile.output_sensitivity),
            }
        )
    )
    return ToolFingerprint(
        structural_hash=_stable_hash(structural),
        semantic_hash=_stable_hash(semantic_tokens),
        semantic_tokens=semantic_tokens,
    )


def semantic_drift(previous: ToolFingerprint, current: ToolFingerprint) -> float:
    left = set(previous.semantic_tokens)
    right = set(current.semantic_tokens)
    if not left and not right:
        return 0.0
    return 1.0 - (len(left & right) / len(left | right))


def _stable_hash(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode()).hexdigest()
