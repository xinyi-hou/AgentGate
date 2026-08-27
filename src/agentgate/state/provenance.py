from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import unicodedata
from collections.abc import Iterable
from typing import Any
from urllib.parse import unquote

from agentgate.events.models import DataType
from agentgate.state.models import SensitiveObject

FIELD_TYPES: dict[DataType, tuple[str, ...]] = {
    DataType.CREDENTIAL: ("token", "credential", "password", "api_key", "private_key"),
    DataType.SECRET: ("secret", "classified", "confidential"),
    DataType.PERSONAL: ("name", "email", "phone", "address", "customer", "recipient"),
    DataType.FINANCIAL: ("amount", "price", "payment", "card", "iban", "wallet", "refund"),
    DataType.INTERNAL: ("internal", "private"),
}


def infer_output_types(output: Any) -> set[DataType]:
    inferred: set[DataType] = set()
    for path, value in flatten_values(output):
        field = next((part.lower() for part in reversed(path) if not part.isdigit()), "")
        rendered = str(value).lower()
        for data_type, words in FIELD_TYPES.items():
            if any(
                word in field or re.search(rf"\b{re.escape(word)}\b", rendered) for word in words
            ):
                inferred.add(data_type)
    return inferred


def match_sensitive_objects(
    arguments: dict[str, Any],
    objects: Iterable[SensitiveObject],
) -> list[SensitiveObject]:
    argument_signatures = {
        signature
        for _, value in flatten_values(arguments)
        for signature in value_signatures(str(value))
    }
    matches = [
        sensitive_object
        for sensitive_object in objects
        if argument_signatures.intersection(sensitive_object.fingerprints)
    ]
    return sorted(matches, key=lambda item: item.object_id)


def fingerprints_for(value: Any) -> list[str]:
    signatures = {
        signature
        for _, scalar in flatten_values(value)
        for signature in value_signatures(str(scalar))
    }
    return sorted(signatures)


def value_signatures(value: str) -> set[str]:
    variants = {value, unquote(value)}
    decoded = _decode_base64(value)
    if decoded is not None:
        variants.add(decoded)
    signatures: set[str] = set()
    for variant in variants:
        normalized = _normalize(variant)
        if len(normalized) < 4:
            continue
        signatures.add(f"normalized_sha256:{hashlib.sha256(normalized.encode()).hexdigest()}")
        compact = re.sub(r"[^a-z0-9@.+/_:-]", "", normalized)
        if len(compact) >= 4:
            signatures.add(f"compact_sha256:{hashlib.sha256(compact.encode()).hexdigest()}")
        signatures.add(f"sha256:{hashlib.sha256(normalized.encode()).hexdigest()}")
    lowered = value.strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", lowered):
        signatures.add(f"sha256:{lowered}")
    return signatures


def flatten_values(value: Any, path: tuple[str, ...] = ()) -> list[tuple[tuple[str, ...], Any]]:
    output: list[tuple[tuple[str, ...], Any]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            output.extend(flatten_values(item, (*path, str(key))))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            output.extend(flatten_values(item, (*path, str(index))))
    elif isinstance(value, (str, int, float)) and not isinstance(value, bool):
        output.append((path or ("value",), value))
    return output


def digest_payload(value: Any) -> str:
    rendered = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(rendered.encode()).hexdigest()


def _normalize(value: str) -> str:
    return re.sub(r"\s+", " ", unicodedata.normalize("NFKC", value)).strip().lower()


def _decode_base64(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 8 or len(compact) % 4:
        return None
    try:
        decoded = base64.b64decode(compact, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    return decoded if decoded.isprintable() else None
