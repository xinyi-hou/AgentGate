from __future__ import annotations

import json
import re
from typing import Any

from agentgate.models import Sensitivity, ToolProfile

FIELD_LABELS = {
    Sensitivity.CREDENTIAL: ("token", "secret", "password", "credential", "api_key"),
    Sensitivity.PERSONAL: ("name", "email", "phone", "address", "customer"),
    Sensitivity.FINANCIAL: ("amount", "price", "payment", "card", "refund"),
    Sensitivity.RESTRICTED: ("classified", "restricted", "private_key"),
}


def label_output(output: Any, profile: ToolProfile) -> set[Sensitivity]:
    labels = set(profile.output_sensitivity)
    text = json.dumps(output, ensure_ascii=False, default=str).lower()
    for label, words in FIELD_LABELS.items():
        if any(re.search(rf"\b{re.escape(word)}\b", text) for word in words):
            labels.add(label)
    return labels


def contains_tracked_data(
    arguments: dict[str, Any], tracked: dict[str, set[Sensitivity]]
) -> set[Sensitivity]:
    text = json.dumps(arguments, ensure_ascii=False, sort_keys=True, default=str).lower()
    labels: set[Sensitivity] = set()
    for fragment, fragment_labels in tracked.items():
        normalized = fragment.strip().lower()
        if len(normalized) >= 4 and normalized in text:
            labels.update(fragment_labels)
    return labels


def track_fragments(output: Any, labels: set[Sensitivity]) -> dict[str, set[Sensitivity]]:
    if not labels:
        return {}
    values: list[str] = []
    _flatten(output, values)
    return {value: set(labels) for value in values if len(value.strip()) >= 4}


def _flatten(value: Any, output: list[str]) -> None:
    if isinstance(value, dict):
        for item in value.values():
            _flatten(item, output)
    elif isinstance(value, list):
        for item in value:
            _flatten(item, output)
    elif isinstance(value, (str, int, float)):
        output.append(str(value))
