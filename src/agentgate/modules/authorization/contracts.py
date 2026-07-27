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
        actions = _task_actions(task)
        resources = set(_task_resources(task))
        if not resources:
            resources = set(entitlements.get("resources", {"*"}))
        entitled_resources = set(entitlements.get("resources", resources))
        allowed_resources = (
            resources
            if "*" in entitled_resources
            else {
                resource
                for resource in resources
                if resource in entitled_resources
                or any(resource.startswith(item.removesuffix("*")) for item in entitled_resources)
            }
        )
        allowed_actions = set(actions)
        allowed_actions &= {
            Action(value) for value in entitlements.get("actions", [item.value for item in Action])
        }
        contract = TaskContract(
            principal=principal,
            goal=task,
            allowed_actions=allowed_actions,
            allowed_resources=allowed_resources,
            allowed_effects=_effects_for_actions(actions),
            forbidden_effects={"data_export", "state_change", "external_transmission"}
            - _effects_for_actions(actions),
            max_records=_task_limit(task),
            external_transmission=Action.TRANSMIT in actions,
        )
        contract = _constrain_to_entitlements(contract, entitlements)
        if self.llm and self.llm.available:
            enriched = await self._enrich(task, contract)
            if enriched:
                contract = _constrain_to_entitlements(enriched, entitlements)
        return contract

    async def _enrich(self, task: str, fallback: TaskContract) -> TaskContract | None:
        assert self.llm is not None
        result = await self.llm.analyze_json(
            system_prompt=(
                "Convert a user task into a least-privilege authorization contract. Do not "
                "grant actions or resources not explicitly required. Return only JSON."
            ),
            payload={"task": task, "principal": fallback.principal},
            schema_hint={
                "allowed_actions": ["READ"],
                "allowed_resources": ["resource:id"],
                "allowed_effects": ["data_read"],
                "forbidden_effects": ["data_export"],
                "max_records": 1,
                "external_transmission": False,
                "allowed_destinations": [],
                "confidence": 0.0,
            },
        )
        if not result:
            return None
        try:
            confidence = float(result.get("confidence", 0.0))
            if confidence < self.confidence_threshold:
                return None
            allowed_effects = set(result.get("allowed_effects", []))
            return fallback.model_copy(
                update={
                    "allowed_actions": {Action(v) for v in result["allowed_actions"]},
                    "allowed_resources": set(result["allowed_resources"]),
                    "allowed_effects": allowed_effects,
                    "forbidden_effects": set(result.get("forbidden_effects", [])),
                    "max_records": int(result.get("max_records", 1)),
                    "external_transmission": bool(
                        result.get("external_transmission", False)
                    ),
                    "allowed_destinations": set(result.get("allowed_destinations", [])),
                    "metadata": {
                        **fallback.metadata,
                        "contract_source": "rules+llm",
                        "semantic_confidence": confidence,
                    },
                }
            )
        except (KeyError, TypeError, ValueError):
            return None


def _task_actions(task: str) -> set[Action]:
    lowered = task.lower()
    mapping = (
        (Action.DELETE, ("delete", "remove", "删除")),
        (
            Action.TRANSMIT,
            (
                "send",
                "email",
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
                "更新",
                "退款",
            ),
        ),
        (
            Action.READ,
            (
                "query",
                "read",
                "get",
                "view",
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
    actions = {action for action, words in mapping if any(word in lowered for word in words)}
    if re.search(
        r"(?:^|\b(?:and|then)\s+)(?:please\s+)?email\b|"
        r"\bemail\s+(?:him|her|them|the|a|an|[\w.+-]+@)",
        lowered,
    ):
        actions.add(Action.TRANSMIT)
    if actions & {
        Action.WRITE,
        Action.DELETE,
        Action.EXECUTE,
        Action.TRANSMIT,
        Action.CONFIGURE,
    }:
        actions.add(Action.READ)
    return actions


def _task_resources(task: str) -> list[str]:
    resources: list[str] = []
    patterns = (
        (r"\b([A-Z]\d{2,})\b", "order"),
        (r"\border[:\s#-]*([A-Za-z0-9_-]+)", "order"),
        (r"\baccount[:\s#-]*([A-Za-z0-9_-]+)", "account"),
        (r"\bservice[:\s#-]*([A-Za-z0-9_-]+)", "service"),
        (r"订单\s*([A-Za-z0-9_-]+)", "order"),
        (r"账户\s*([A-Za-z0-9_-]+)", "account"),
    )
    for pattern, kind in patterns:
        for match in re.findall(pattern, task, flags=re.I):
            resources.append(f"{kind}:{match}")
    return resources


def _task_limit(task: str) -> int:
    match = re.search(r"\b(?:limit|最多|前)\s*(\d+)", task, flags=re.I)
    return int(match.group(1)) if match else 1


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
            updates["forbidden_effects"] = contract.forbidden_effects | {
                "external_transmission"
            }

    if "resources" in entitlements:
        entitled_resources = {str(value) for value in entitlements["resources"]}  # type: ignore[index]
        if "*" not in entitled_resources:
            updates["allowed_resources"] = {
                resource
                for resource in contract.allowed_resources
                if resource in entitled_resources
                or any(
                    resource.startswith(pattern.removesuffix("*"))
                    for pattern in entitled_resources
                )
            }

    if "effects" in entitlements:
        entitled_effects = {str(value) for value in entitlements["effects"]}  # type: ignore[index]
        current_effects = set(updates.get("allowed_effects", contract.allowed_effects))
        updates["allowed_effects"] = current_effects & entitled_effects

    if "max_records" in entitlements:
        updates["max_records"] = min(contract.max_records, int(entitlements["max_records"]))

    return contract.model_copy(update=updates)


def _compatible_effects_for_actions(actions: set[Action]) -> set[str]:
    compatible = _effects_for_actions(actions)
    if Action.READ in actions:
        compatible.update({"data_export", "credential_access"})
    if Action.WRITE in actions:
        compatible.update({"financial_transaction", "credential_creation"})
    return compatible
