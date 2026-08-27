from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

from agentgate.events.models import EffectType, SecurityOperation


class TaskContract(BaseModel):
    principal: str
    task_id: str | None = None
    goal: str
    allowed_operations: set[SecurityOperation]
    allowed_resource_patterns: set[str] = Field(default_factory=lambda: {"*"})
    allowed_effects: set[EffectType] = Field(default_factory=set)
    forbidden_effects: set[EffectType] = Field(default_factory=set)
    max_records: int | None = Field(default=None, ge=0)
    allowed_destinations: set[str] = Field(default_factory=set)
    source: str = "explicit"
    evidence: list[str] = Field(default_factory=list)


_ACTION_TERMS: tuple[tuple[SecurityOperation, tuple[str, ...]], ...] = (
    (SecurityOperation.DELETE, ("delete", "remove", "destroy", "删除")),
    (SecurityOperation.AUTH, ("login", "authenticate", "grant access", "登录", "授权")),
    (SecurityOperation.INSTALL, ("install", "deploy", "安装", "部署")),
    (SecurityOperation.EXECUTE, ("execute", "run", "restart", "执行", "运行", "重启")),
    (
        SecurityOperation.SEND,
        ("send", "email", "upload", "post", "share", "transfer", "发送", "上传", "分享"),
    ),
    (
        SecurityOperation.WRITE,
        (
            "write",
            "update",
            "create",
            "book",
            "reserve",
            "schedule",
            "change",
            "refund",
            "cancel",
            "写入",
            "更新",
            "创建",
            "预订",
            "退款",
            "取消",
        ),
    ),
    (
        SecurityOperation.READ,
        (
            "read",
            "get",
            "fetch",
            "retrieve",
            "view",
            "show",
            "find",
            "search",
            "list",
            "check",
            "status",
            "detail",
            "what",
            "where",
            "when",
            "查询",
            "读取",
            "查看",
            "搜索",
            "状态",
        ),
    ),
)


class TaskContractCompiler:
    """Compiles explicit task text into bounded facts; it never expands entitlements."""

    def compile(
        self,
        goal: str,
        *,
        principal: str,
        task_id: str | None = None,
        entitlements: dict[str, Any] | None = None,
    ) -> TaskContract:
        lowered = goal.lower()
        inferred = {
            operation
            for operation, terms in _ACTION_TERMS
            if any(_contains(lowered, term) for term in terms)
        }
        if inferred - {SecurityOperation.READ}:
            inferred.add(SecurityOperation.READ)

        entitlements = entitlements or {}
        ceiling = {
            SecurityOperation(value)
            for value in entitlements.get(
                "operations", [operation.value for operation in SecurityOperation]
            )
        }
        operations = inferred & ceiling
        resources = set(_resource_mentions(goal)) or {"*"}
        entitled_resources = set(entitlements.get("resources", {"*"}))
        if "*" not in entitled_resources:
            resources = {
                resource
                for resource in resources
                if any(_resource_covered(resource, item) for item in entitled_resources)
            }
        destinations = set(_destinations(goal))
        effects = _effects_for(operations)
        entitled_effects = {
            EffectType(value)
            for value in entitlements.get("effects", [effect.value for effect in EffectType])
        }
        effects &= entitled_effects
        return TaskContract(
            principal=principal,
            task_id=task_id,
            goal=goal,
            allowed_operations=operations,
            allowed_resource_patterns=resources,
            allowed_effects=effects,
            forbidden_effects=set(EffectType) - effects,
            max_records=_record_limit(goal),
            allowed_destinations=destinations,
            source="deterministic_compiler",
            evidence=[f"operation:{item.value}" for item in sorted(operations, key=str)],
        )


def _contains(text: str, term: str) -> bool:
    if term.isascii():
        return bool(re.search(rf"(?<![a-z0-9_]){re.escape(term)}(?![a-z0-9_])", text))
    return term in text


def _resource_mentions(goal: str) -> list[str]:
    patterns = (
        (r"\border(?:\s+(?:id|number|#))?\s*[:#-]?\s*([A-Za-z]*\d[\w-]*)", "order"),
        (r"\baccount(?:\s+(?:id|number))?\s*[:#-]?\s*([A-Za-z]*\d[\w-]*)", "account"),
        (r"\bfile\s+([/\.\w-]+)", "file"),
        (r"订单\s*([A-Za-z0-9_-]+)", "order"),
        (r"账户\s*([A-Za-z0-9_-]+)", "account"),
    )
    return [
        f"{kind}:{match}"
        for pattern, kind in patterns
        for match in re.findall(pattern, goal, flags=re.IGNORECASE)
    ]


def _destinations(goal: str) -> list[str]:
    return [
        *re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", goal),
        *re.findall(r"https?://[^\s,;]+", goal, flags=re.IGNORECASE),
    ]


def _record_limit(goal: str) -> int:
    match = re.search(
        r"\b(?:limit|top|last|latest|recent)\s*(\d+)\b|(?:最多|前|最近)\s*(\d+)",
        goal,
        re.I,
    )
    if match:
        return int(next(item for item in match.groups() if item is not None))
    broad = re.search(
        r"\b(?:all|list|search|summary|history)\b|所有|列表|汇总|历史",
        goal,
        re.I,
    )
    return 100 if broad else 1


def _effects_for(operations: set[SecurityOperation]) -> set[EffectType]:
    mapping = {
        SecurityOperation.SEND: {EffectType.EXTERNAL},
        SecurityOperation.WRITE: {EffectType.PERSISTENT},
        SecurityOperation.DELETE: {
            EffectType.PERSISTENT,
            EffectType.DESTRUCTIVE,
            EffectType.IRREVERSIBLE,
        },
        SecurityOperation.EXECUTE: {EffectType.PRIVILEGED},
        SecurityOperation.AUTH: {EffectType.PRIVILEGED},
        SecurityOperation.INSTALL: {EffectType.PERSISTENT, EffectType.PRIVILEGED},
    }
    return {effect for operation in operations for effect in mapping.get(operation, set())}


def _resource_covered(resource: str, ceiling: str) -> bool:
    return ceiling == "*" or resource == ceiling or resource.startswith(f"{ceiling}:")
