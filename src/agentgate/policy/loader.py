from __future__ import annotations

from importlib.resources import files
from pathlib import Path

import yaml

from agentgate.policy.models import SecurityPolicy


def load_policy(path: str | Path | None = None) -> SecurityPolicy:
    if path is None:
        resource = files("agentgate.policy.default_rules").joinpath("default.yaml")
        raw = resource.read_text(encoding="utf-8")
    else:
        raw = Path(path).read_text(encoding="utf-8")
    payload = yaml.safe_load(raw) or {}
    return SecurityPolicy.model_validate(payload)
