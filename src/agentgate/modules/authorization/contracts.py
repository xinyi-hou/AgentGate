from __future__ import annotations

import re

from agentgate.llm import LLMAnalyzer
from agentgate.models import Action, TaskContract


class TaskContractBuilder:
    def __init__(self, llm: LLMAnalyzer | None = None, confidence_threshold: float = 0.75):
        self.llm = llm
        self.confidence_threshold = confidence_threshold

    async def build(
        self,
        task: str,
        principal: str,
        entitlements: dict[str, object] | None = None,
    ) -> TaskContract:
        entitlements = entitlements or {}
        entitled_actions = {
            Action(value)
            for value in entitlements.get("actions", [item.value for item in Action])
        }
        actions = _task_actions(task)
        task_effects = _effects_for_actions(actions)
        if _is_financial_task(task):
            task_effects.add("financial_transaction")
        resources = set(_task_resources(task))
        task_resource_open = not resources
        resource_catalog_open = "*" in set(entitlements.get("resources", set()))
        entitled_resources = set(entitlements.get("resources", resources))
        if not resources and "*" in entitled_resources:
            # An open resource catalog is a ceiling, not evidence that every resource is
            # task-relevant. Semantic call alignment narrows this open-world fallback.
            resources = {"*"}
        allowed_resources = (
            resources
            if "*" in entitled_resources
            else {
                resource for resource in resources if _matches_ceiling(resource, entitled_resources)
            }
        )
        allowed_actions = set(actions)
        allowed_actions &= entitled_actions
        contract = TaskContract(
            principal=principal,
            goal=task,
            allowed_actions=allowed_actions,
            allowed_resources=allowed_resources,
            allowed_effects=task_effects,
            forbidden_effects={"data_export", "state_change", "external_transmission"}
            - task_effects,
            max_records=_task_limit(task),
            external_transmission=Action.TRANSMIT in actions,
            allowed_destinations=set(_task_destinations(task)),
            confirmed_actions=actions & {Action.WRITE, Action.TRANSMIT, Action.CONFIGURE},
            metadata={
                "resource_catalog_open": resource_catalog_open,
                "task_resource_open": task_resource_open,
                "destination_open": Action.TRANSMIT in actions and not _task_destinations(task),
                "read_entitled": Action.READ in entitled_actions,
                "supporting_action_ceiling": (
                    [Action.READ.value, Action.UNKNOWN.value]
                    if Action.READ in entitled_actions
                    else []
                ),
                "action_ceiling": sorted(action.value for action in entitled_actions),
                "effect_ceiling": sorted(_compatible_effects_for_actions(entitled_actions)),
                "authorization_context": str(entitlements.get("policy_context", ""))[:6000],
            },
        )
        contract = _constrain_to_entitlements(contract, entitlements)
        if self.llm and self.llm.available:
            enriched = await self._enrich(task, contract, entitlements)
            if enriched:
                contract = _constrain_semantic_contract(enriched, contract, entitlements)
        return contract

    async def _enrich(
        self,
        task: str,
        fallback: TaskContract,
        entitlements: dict[str, object],
    ) -> TaskContract | None:
        assert self.llm is not None
        result = await self.llm.analyze_json(
            system_prompt=(
                "Extract bounded authorization facts explicitly required by a user task. Do not "
                "make an allow/deny decision and do not output confidence or arbitrary policy "
                "effects. Actions must be READ, WRITE, DELETE, EXECUTE, TRANSMIT, or CONFIGURE. "
                "Return JSON only."
            ),
            payload={
                "task": task,
                "principal": fallback.principal,
                "rule_contract": fallback.model_dump(mode="json"),
                "enterprise_entitlements": entitlements,
            },
            schema_hint={
                "explicit_actions": ["READ"],
                "resource_mentions": ["resource:id"],
                "max_records": 1,
                "external_destinations": [],
            },
        )
        if not result:
            return None
        try:
            raw_actions = result.get("explicit_actions", result.get("allowed_actions", []))
            actions = {Action(value) for value in raw_actions}
            resources = {
                _normalize_resource(value)
                for value in result.get("resource_mentions", result.get("allowed_resources", []))
            }
            resources.discard("")
            destinations = {
                str(value).strip()
                for value in result.get(
                    "external_destinations", result.get("allowed_destinations", [])
                )
                if str(value).strip()
            }
            effects = _effects_for_actions(actions)
            return fallback.model_copy(
                update={
                    "allowed_actions": actions,
                    "allowed_resources": resources,
                    "allowed_effects": effects,
                    "forbidden_effects": {
                        "data_export",
                        "state_change",
                        "external_transmission",
                    }
                    - effects,
                    "max_records": int(result.get("max_records", 1)),
                    "external_transmission": Action.TRANSMIT in actions,
                    "allowed_destinations": destinations,
                    "confirmed_actions": actions
                    & {Action.WRITE, Action.TRANSMIT, Action.CONFIGURE},
                    "metadata": {
                        **fallback.metadata,
                        "contract_source": "rules+llm",
                        "semantic_mode": "bounded_facts",
                    },
                }
            )
        except (KeyError, TypeError, ValueError):
            return None


def _task_actions(task: str) -> set[Action]:
    lowered = task.lower()
    mapping = (
        (Action.DELETE, ("delete", "remove", "terminate", "删除")),
        (
            Action.TRANSMIT,
            (
                "send",
                "upload",
                "post",
                "reply",
                "transfer",
                "share",
                "发送",
                "上传",
            ),
        ),
        (Action.EXECUTE, ("execute", "restart", "run", "执行", "重启")),
        (
            Action.WRITE,
            (
                "update",
                "write",
                "refund",
                "book",
                "reserve",
                "schedule",
                "create",
                "adjust",
                "change",
                "increase",
                "add",
                "append",
                "edit",
                "invite",
                "fix",
                "resolve",
                "troubleshoot",
                "return",
                "exchange",
                "replace",
                "refuel",
                "resume",
                "cancel",
                "取消",
                "更新",
                "退款",
            ),
        ),
        (
            Action.CONFIGURE,
            (
                "configure",
                "enable",
                "disable",
                "activate",
                "deactivate",
                "toggle",
                "set",
                "reset",
                "grant",
                "reseat",
                "connect",
                "disconnect",
                "fix",
                "troubleshoot",
            ),
        ),
        (
            Action.READ,
            (
                "query",
                "read",
                "get",
                "fetch",
                "retrieve",
                "view",
                "show",
                "describe",
                "detail",
                "details",
                "information",
                "status",
                "find",
                "search",
                "list",
                "look",
                "see",
                "review",
                "summarize",
                "analyze",
                "analysis",
                "assess",
                "evaluate",
                "recommend",
                "identify",
                "determine",
                "provide",
                "compare",
                "check",
                "calculate",
                "total",
                "what",
                "how much",
                "查询",
                "查看",
                "读取",
            ),
        ),
    )
    actions = {
        action
        for action, words in mapping
        if any(_contains_task_term(lowered, word) for word in words)
    }
    if re.search(
        r"(?:^|\b(?:and|then)\s+)(?:please\s+)?email\b|"
        r"\bemail\s+(?:him|her|them|the|a|an|[\w.+-]+@)",
        lowered,
    ):
        actions.add(Action.TRANSMIT)
    if _is_financial_task(task):
        actions.add(Action.WRITE)
        actions.discard(Action.TRANSMIT)
    if actions & {
        Action.WRITE,
        Action.DELETE,
        Action.EXECUTE,
        Action.TRANSMIT,
        Action.CONFIGURE,
    }:
        actions.add(Action.READ)
    return actions


def _normalize_resource(value: object) -> str:
    return re.sub(r"[^a-zA-Z0-9_.:*\-/]+", "_", str(value).strip()).strip("_")[:128]


def _contains_task_term(task: str, term: str) -> bool:
    if term.isascii():
        return bool(re.search(rf"(?<![a-z0-9_]){re.escape(term)}(?![a-z0-9_])", task))
    return term in task


def _task_resources(task: str) -> list[str]:
    resources: list[str] = []
    patterns = (
        (
            r"\border(?:\s+(?:id|number|#)|[:#-]+)?\s*"
            r"([A-Za-z]*\d[A-Za-z0-9_-]*)",
            "order",
        ),
        (
            r"\baccount(?:\s+(?:id|number)|[:#-]+)?\s*"
            r"((?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]+)",
            "account",
        ),
        (
            r"\bservice(?:\s+(?:id|number)|[:#-]+)?\s*"
            r"((?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]+)",
            "service",
        ),
        (r"订单\s*([A-Za-z0-9_-]+)", "order"),
        (r"账户\s*([A-Za-z0-9_-]+)", "account"),
    )
    for pattern, kind in patterns:
        for match in re.findall(pattern, task, flags=re.I):
            resources.append(f"{kind}:{match}")
    return resources


def _task_limit(task: str) -> int:
    patterns = (
        r"\b(?:limit|top|last|latest|recent|most recent)\s*(\d+)",
        r"(?:最多|前|最近)\s*(\d+)",
    )
    for pattern in patterns:
        if match := re.search(pattern, task, flags=re.I):
            return int(match.group(1))
    if re.search(
        r"\b(?:total|compare|historical|history|during|between|all|list|search|summary|"
        r"summarize|calendar|schedule)\b|总计|汇总|历史|期间|所有|列表|搜索",
        task,
        flags=re.I,
    ):
        return 100
    return 20


def _task_destinations(task: str) -> list[str]:
    emails = re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", task)
    urls = re.findall(r"https?://[^\s,;]+", task, flags=re.I)
    return [*emails, *urls]


def _effects_for_actions(actions: set[Action]) -> set[str]:
    mapping = {
        Action.READ: {"data_read"},
        Action.WRITE: {"state_change"},
        Action.DELETE: {"state_change", "destructive"},
        Action.EXECUTE: {"code_execution", "state_change"},
        Action.TRANSMIT: {"external_transmission"},
        Action.CONFIGURE: {"state_change"},
    }
    return {effect for action in actions for effect in mapping.get(action, set())}


def _is_financial_task(task: str) -> bool:
    return bool(
        re.search(r"\b(?:send|pay|transfer|refund|reallocate|redirect)\b", task, flags=re.I)
        and re.search(
            r"[$€£¥]|\b(?:money|funds?|payment|transaction|price|amount|difference)\b",
            task,
            flags=re.I,
        )
    )


def _constrain_to_entitlements(
    contract: TaskContract,
    entitlements: dict[str, object],
) -> TaskContract:
    updates: dict[str, object] = {}
    allowed_actions = set(contract.allowed_actions)
    if "actions" in entitlements:
        entitled_actions = {Action(value) for value in entitlements["actions"]}  # type: ignore[index]
        allowed_actions &= entitled_actions
        updates["allowed_actions"] = allowed_actions

        compatible_effects = _compatible_effects_for_actions(allowed_actions)
        updates["allowed_effects"] = contract.allowed_effects & compatible_effects
        if Action.TRANSMIT not in allowed_actions:
            updates["external_transmission"] = False
            updates["allowed_destinations"] = set()
            updates["forbidden_effects"] = contract.forbidden_effects | {"external_transmission"}

    if "resources" in entitlements:
        entitled_resources = {str(value) for value in entitlements["resources"]}  # type: ignore[index]
        if "*" not in entitled_resources:
            updates["allowed_resources"] = {
                resource
                for resource in contract.allowed_resources
                if _matches_ceiling(resource, entitled_resources)
            }

    if "effects" in entitlements:
        entitled_effects = {str(value) for value in entitlements["effects"]}  # type: ignore[index]
        current_effects = set(updates.get("allowed_effects", contract.allowed_effects))
        updates["allowed_effects"] = current_effects & entitled_effects

    if "max_records" in entitlements:
        updates["max_records"] = min(contract.max_records, int(entitlements["max_records"]))

    if "destinations" in entitlements:
        entitled_destinations = {
            str(value)
            for value in entitlements["destinations"]  # type: ignore[index]
        }
        if "*" not in entitled_destinations:
            updates["allowed_destinations"] = contract.allowed_destinations & entitled_destinations

    if "external_transmission" in entitlements and not bool(entitlements["external_transmission"]):
        updates["external_transmission"] = False
        updates["allowed_destinations"] = set()
        updates["forbidden_effects"] = contract.forbidden_effects | {"external_transmission"}

    return contract.model_copy(update=updates)


def _constrain_semantic_contract(
    contract: TaskContract,
    fallback: TaskContract,
    entitlements: dict[str, object],
) -> TaskContract:
    if "actions" in entitlements:
        action_ceiling = {Action(value) for value in entitlements["actions"]}  # type: ignore[index]
    else:
        action_ceiling = set(fallback.allowed_actions)
    allowed_actions = contract.allowed_actions & action_ceiling

    if "resources" in entitlements:
        resource_ceiling = {
            str(value)
            for value in entitlements["resources"]  # type: ignore[index]
        }
    else:
        resource_ceiling = set(fallback.allowed_resources)
    allowed_resources = {
        resource
        for resource in contract.allowed_resources
        if _matches_ceiling(resource, resource_ceiling)
    }

    if "effects" in entitlements:
        effect_ceiling = {str(value) for value in entitlements["effects"]}  # type: ignore[index]
    elif "actions" in entitlements:
        effect_ceiling = _compatible_effects_for_actions(action_ceiling)
    else:
        effect_ceiling = set(fallback.allowed_effects)
    allowed_effects = contract.allowed_effects & effect_ceiling

    if "actions" in entitlements:
        forbidden_effects = set(contract.forbidden_effects) - allowed_effects
    else:
        forbidden_effects = (
            fallback.forbidden_effects | contract.forbidden_effects
        ) - allowed_effects

    record_ceiling = (
        int(entitlements["max_records"]) if "max_records" in entitlements else fallback.max_records
    )
    external_transmission = (
        contract.external_transmission
        and Action.TRANSMIT in allowed_actions
        and "external_transmission" in allowed_effects
        and bool(entitlements.get("external_transmission", True))
    )
    allowed_destinations = set(contract.allowed_destinations)
    if "destinations" in entitlements:
        destination_ceiling = {
            str(value)
            for value in entitlements["destinations"]  # type: ignore[index]
        }
        if "*" not in destination_ceiling:
            allowed_destinations &= destination_ceiling
    if not external_transmission:
        allowed_destinations = set()

    return contract.model_copy(
        update={
            "allowed_actions": allowed_actions,
            "allowed_resources": allowed_resources,
            "allowed_effects": allowed_effects,
            "forbidden_effects": forbidden_effects,
            "max_records": min(contract.max_records, record_ceiling),
            "external_transmission": external_transmission,
            "allowed_destinations": allowed_destinations,
        }
    )


def _matches_ceiling(value: str, ceiling: set[str]) -> bool:
    if "*" in ceiling:
        return True
    return any(
        value == pattern or (pattern.endswith("*") and value.startswith(pattern[:-1]))
        for pattern in ceiling
    )


def _compatible_effects_for_actions(actions: set[Action]) -> set[str]:
    compatible = _effects_for_actions(actions)
    if Action.READ in actions:
        compatible.update({"data_export", "credential_access"})
    if Action.WRITE in actions:
        compatible.update({"financial_transaction", "credential_creation"})
    return compatible
