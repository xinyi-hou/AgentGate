from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from agentgate.models import TaskContract, ToolSpec


class BenchmarkStep(BaseModel):
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    approval_token: str | None = None
    expected: str


class BenchmarkCase(BaseModel):
    id: str
    category: str
    risk_type: str
    kind: Literal["content", "registration", "semantic_drift", "trajectory"]
    split: Literal["train", "dev", "test"] = "test"
    malicious: bool
    content: str | None = None
    tool_spec: ToolSpec | None = None
    tool_versions: list[ToolSpec] = Field(default_factory=list)
    contract: TaskContract | None = None
    steps: list[BenchmarkStep] = Field(default_factory=list)
    settings: dict[str, Any] = Field(default_factory=dict)
    tags: set[str] = Field(default_factory=set)


def load_cases(path: str | Path, split: str | None = None) -> list[BenchmarkCase]:
    cases: list[BenchmarkCase] = []
    with Path(path).open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                case = BenchmarkCase.model_validate_json(line)
            except Exception as exc:
                raise ValueError(f"invalid benchmark case at line {line_number}: {exc}") from exc
            if split is None or case.split == split:
                cases.append(case)
    return cases


def resolve_templates(value: Any, previous: Any) -> Any:
    if isinstance(value, dict):
        return {key: resolve_templates(item, previous) for key, item in value.items()}
    if isinstance(value, list):
        return [resolve_templates(item, previous) for item in value]
    if isinstance(value, str) and value.startswith("$last"):
        current = previous
        for part in value.split(".")[1:]:
            if isinstance(current, list) and part.isdigit():
                current = current[int(part)]
            elif isinstance(current, dict):
                current = current[part]
            else:
                raise KeyError(f"cannot resolve template {value}")
        return current
    return value
