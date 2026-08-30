from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import timedelta
from typing import Any

from agentgate.authorization.models import TaskAuthorization, TaskIntent
from agentgate.events.models import EffectType, SecurityOperation, utc_now

_ACTION_TERMS: tuple[tuple[SecurityOperation, tuple[str, ...]], ...] = (
    (SecurityOperation.DELETE, ("delete", "remove", "destroy", "删除")),
    (SecurityOperation.PRIVILEGE, ("grant role", "chmod", "chown", "sudo", "提升权限")),
    (SecurityOperation.AUTH, ("login", "authenticate", "token exchange", "登录", "认证")),
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
            "add",
            "append",
            "adjust",
            "reschedule",
            "reservation",
            "invite",
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
            "how much",
            "how many",
            "查询",
            "读取",
            "查看",
            "搜索",
            "状态",
        ),
    ),
)


class TaskAuthorizationCompiler:
    """Compile task intent against an external entitlement ceiling."""

    def compile(
        self,
        intent: TaskIntent,
        *,
        principal: str,
        entitlements: dict[str, Any],
        issuer: str,
        signing_key: bytes | None = None,
        ttl_seconds: int | None = 3600,
    ) -> TaskAuthorization:
        inferred = {
            operation
            for operation, terms in _ACTION_TERMS
            if any(_contains(intent.goal.lower(), term) for term in terms)
        }
        if not inferred and re.search(
            r"\b(?:who|which|how|is|are|did|does|do|can)\b", intent.goal, re.IGNORECASE
        ):
            inferred.add(SecurityOperation.READ)
        if inferred - {SecurityOperation.READ}:
            inferred.add(SecurityOperation.READ)
        ceiling = {SecurityOperation(value) for value in entitlements.get("operations", [])}
        operations = inferred & ceiling

        resources = set(_resource_mentions(intent.goal)) or {"*"}
        entitled_resources = set(entitlements.get("resources", []))
        if "*" not in entitled_resources:
            resources = {
                resource
                for resource in resources
                if any(_resource_covered(resource, item) for item in entitled_resources)
            }
        destinations = set(_destinations(intent.goal))
        entitled_destinations = set(entitlements.get("destinations", []))
        if "*" not in entitled_destinations:
            destinations &= entitled_destinations
        effects = _effects_for(operations)
        entitled_effects = {EffectType(value) for value in entitlements.get("effects", [])}
        effects &= entitled_effects
        issued_at = utc_now()
        authorization = TaskAuthorization(
            principal=principal,
            task_id=intent.task_id,
            allowed_operations=operations,
            allowed_resource_patterns=sorted(resources),
            allowed_effects=effects,
            forbidden_effects=set(EffectType) - effects,
            max_records=min(
                _record_limit(intent.goal),
                int(entitlements.get("max_records", _record_limit(intent.goal))),
            ),
            allowed_destinations=sorted(destinations),
            issuer=issuer,
            issued_at=issued_at,
            expires_at=(
                issued_at + timedelta(seconds=ttl_seconds) if ttl_seconds is not None else None
            ),
            task_hash=intent.task_hash,
            evidence=[f"operation:{item.value}" for item in sorted(operations, key=str)],
        )
        if signing_key is not None:
            authorization.signature = sign_authorization(authorization, signing_key)
        return authorization


def sign_authorization(authorization: TaskAuthorization, signing_key: bytes) -> str:
    payload = authorization.model_dump(mode="json", exclude={"signature"})
    rendered = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hmac.new(signing_key, rendered.encode(), hashlib.sha256).hexdigest()


def verify_authorization(authorization: TaskAuthorization, signing_key: bytes) -> bool:
    if authorization.signature is None:
        return False
    expected = sign_authorization(authorization, signing_key)
    return hmac.compare_digest(authorization.signature, expected)


def _contains(text: str, term: str) -> bool:
    if term.isascii():
        return bool(re.search(rf"(?<![a-z0-9_]){re.escape(term)}(?![a-z0-9_])", text))
    return term in text


def _resource_mentions(goal: str) -> list[str]:
    patterns = (
        (r"\border(?:\s+(?:id|number|#))?\s*[:#-]?\s*([A-Za-z]*\d[\w-]*)", "order"),
        (r"\baccount(?:\s+(?:id|number))?\s*[:#-]?\s*([A-Za-z]*\d[\w-]*)", "account"),
        (r"\b(?:file|filename)(?:\s+(?:named|called))?\s+['\"]([^'\"]+)['\"]", "file"),
        (r"\b(?:file|filename)(?:\s+(?:named|called))?\s+([/\.\w-]+)", "file"),
        (r"订单\s*([A-Za-z0-9_-]+)", "order"),
        (r"账户\s*([A-Za-z0-9_-]+)", "account"),
    )
    generic_descriptors = {"called", "containing", "named", "that", "the", "with"}
    return [
        f"{kind}:{match}"
        for pattern, kind in patterns
        for match in re.findall(pattern, goal, flags=re.IGNORECASE)
        if match.lower() not in generic_descriptors
    ]


def _destinations(goal: str) -> list[str]:
    web_hosts = re.findall(
        r"\bwww\.[A-Za-z0-9.-]+(?:/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)?", goal
    )
    return [
        *re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", goal),
        *re.findall(r"https?://[^\s,;]+", goal, flags=re.IGNORECASE),
        *web_hosts,
        *(f"http://{host}" for host in web_hosts),
        *re.findall(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b", goal),
    ]


def _record_limit(goal: str) -> int:
    match = re.search(
        r"\b(?:limit|top|last|latest|recent)\s*(\d+)\b|(?:最多|前|最近)\s*(\d+)",
        goal,
        re.I,
    )
    if match:
        return int(next(item for item in match.groups() if item is not None))
    broad = re.search(r"\b(?:all|list|search|summary|history)\b|所有|列表|汇总|历史", goal, re.I)
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
        SecurityOperation.PRIVILEGE: {EffectType.PRIVILEGED},
        SecurityOperation.INSTALL: {EffectType.PERSISTENT, EffectType.PRIVILEGED},
    }
    return {effect for operation in operations for effect in mapping.get(operation, set())}


def _resource_covered(resource: str, ceiling: str) -> bool:
    return ceiling == "*" or resource == ceiling or resource.startswith(f"{ceiling}:")
