from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote

from agentgate.models import Sensitivity, ToolProfile
from agentgate.modules.trajectory.state import TrackedValue

FIELD_LABELS = {
    Sensitivity.CREDENTIAL: ("token", "secret", "password", "credential", "api_key", "key"),
    Sensitivity.PERSONAL: ("name", "email", "phone", "address", "customer", "recipient"),
    Sensitivity.FINANCIAL: ("amount", "price", "payment", "card", "refund", "iban", "wallet"),
    Sensitivity.RESTRICTED: ("classified", "restricted", "private_key", "confidential"),
}

NEUTRAL_FIELDS = {
    "id",
    "order_id",
    "record_id",
    "status",
    "count",
    "total",
    "type",
    "category",
    "created_at",
    "updated_at",
}


@dataclass(frozen=True)
class TrackedMatch:
    labels: frozenset[Sensitivity]
    source_call_id: str
    source_path: str
    argument_path: str


def label_output(output: Any, profile: ToolProfile) -> set[Sensitivity]:
    labels = set(profile.output_sensitivity)
    text = json.dumps(output, ensure_ascii=False, default=str).lower()
    for label, words in FIELD_LABELS.items():
        if any(re.search(rf"\b{re.escape(word)}\b", text) for word in words):
            labels.add(label)
    return labels


def match_tracked_data(
    arguments: dict[str, Any], tracked: dict[str, TrackedValue]
) -> list[TrackedMatch]:
    matches: dict[tuple[str, str, str], TrackedMatch] = {}
    for path, value in _flatten(arguments):
        rendered = str(value)
        signatures = _signatures(rendered)
        normalized = _normalize(rendered)
        for signature, tracked_value in tracked.items():
            exact = signature in signatures
            contained = (
                signature.startswith("literal:")
                and len(signature) >= len("literal:") + 4
                and signature.removeprefix("literal:") in normalized
            )
            if not exact and not contained:
                continue
            argument_path = ".".join(path)
            key = (tracked_value.source_call_id, tracked_value.source_path, argument_path)
            matches[key] = TrackedMatch(
                labels=frozenset(tracked_value.labels),
                source_call_id=tracked_value.source_call_id,
                source_path=tracked_value.source_path,
                argument_path=argument_path,
            )
    return list(matches.values())


def contains_tracked_data(
    arguments: dict[str, Any], tracked: dict[str, TrackedValue]
) -> set[Sensitivity]:
    return {label for match in match_tracked_data(arguments, tracked) for label in match.labels}


def track_fragments(
    output: Any,
    labels: set[Sensitivity],
    *,
    source_call_id: str = "unknown",
) -> dict[str, TrackedValue]:
    if not labels:
        return {}
    tracked: dict[str, TrackedValue] = {}
    for path, value in _flatten(output):
        rendered = str(value).strip()
        if len(rendered) < 4:
            continue
        value_labels = _labels_for_path(path, labels)
        if not value_labels:
            continue
        item = TrackedValue(
            labels=value_labels,
            source_call_id=source_call_id,
            source_path=".".join(path),
        )
        for signature in _signatures(rendered):
            tracked[signature] = item
    return tracked


def _flatten(value: Any, path: tuple[str, ...] = ()) -> list[tuple[tuple[str, ...], Any]]:
    output: list[tuple[tuple[str, ...], Any]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            output.extend(_flatten(item, (*path, str(key))))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            output.extend(_flatten(item, (*path, str(index))))
    elif isinstance(value, (str, int, float)):
        output.append((path or ("value",), value))
    return output


def _labels_for_path(path: tuple[str, ...], labels: set[Sensitivity]) -> set[Sensitivity]:
    field = next((part.lower() for part in reversed(path) if not part.isdigit()), "value")
    specific = {
        label
        for label, words in FIELD_LABELS.items()
        if label in labels and any(word in field for word in words)
    }
    if specific:
        return specific
    if _is_neutral_field(field) and labels <= {
        Sensitivity.PERSONAL,
        Sensitivity.FINANCIAL,
        Sensitivity.INTERNAL,
    }:
        return {Sensitivity.INTERNAL} if Sensitivity.INTERNAL in labels else set()
    return set(labels)


def _is_neutral_field(field: str) -> bool:
    return field in NEUTRAL_FIELDS or field.endswith(("_id", "_status", "_count", "_type"))


def _signatures(value: str) -> set[str]:
    variants = {value, unquote(value)}
    decoded = _decode_base64(value)
    if decoded is not None:
        variants.add(decoded)
    signatures: set[str] = set()
    for variant in variants:
        normalized = _normalize(variant)
        if len(normalized) < 4:
            continue
        signatures.add(f"literal:{normalized}")
        compact = re.sub(r"[^a-z0-9@.+-]", "", normalized)
        if len(compact) >= 4:
            signatures.add(f"compact:{compact}")
        signatures.add(f"sha256:{hashlib.sha256(normalized.encode()).hexdigest()}")
    lowered = value.strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", lowered):
        signatures.add(f"sha256:{lowered}")
    return signatures


def _normalize(value: str) -> str:
    value = unicodedata.normalize("NFKC", value)
    return re.sub(r"\s+", " ", value).strip().lower()


def _decode_base64(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 8 or len(compact) % 4:
        return None
    try:
        decoded = base64.b64decode(compact, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    return decoded if decoded.isprintable() else None
