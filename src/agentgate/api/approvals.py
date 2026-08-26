from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from agentgate.api.dependencies import get_runtime
from agentgate.api.models import SidecarToolCall
from agentgate.audit.models import AuditEventType, AuditRecord
from agentgate.enforcement.models import ApprovalRequest
from agentgate.runtime.gateway import AgentGateRuntime

router = APIRouter(prefix="/v1/approvals", tags=["approvals"])


class ApprovalCreateRequest(BaseModel):
    call: SidecarToolCall


class ApprovalGrant(BaseModel):
    approval: ApprovalRequest
    approval_token: str


@router.post("", response_model=ApprovalRequest)
async def create_approval(
    request: ApprovalCreateRequest,
    runtime: Annotated[AgentGateRuntime, Depends(get_runtime)],
) -> ApprovalRequest:
    approval = await runtime.approvals.ensure_request(request.call.to_runtime_call())
    await _audit(runtime, approval, "CREATED")
    return approval


@router.post("/{approval_id}/approve", response_model=ApprovalGrant)
async def approve(
    approval_id: str,
    runtime: Annotated[AgentGateRuntime, Depends(get_runtime)],
) -> ApprovalGrant:
    approval, token = await runtime.approvals.approve(approval_id)
    await _audit(runtime, approval, "APPROVED")
    return ApprovalGrant(approval=approval, approval_token=token)


@router.post("/{approval_id}/deny", response_model=ApprovalRequest)
async def deny(
    approval_id: str,
    runtime: Annotated[AgentGateRuntime, Depends(get_runtime)],
) -> ApprovalRequest:
    approval = await runtime.approvals.deny(approval_id)
    await _audit(runtime, approval, "DENIED")
    return approval


async def _audit(
    runtime: AgentGateRuntime,
    approval: ApprovalRequest,
    status: str,
) -> None:
    await runtime.audit.append(
        AuditRecord(
            event_type=AuditEventType.APPROVAL,
            principal=approval.principal,
            session_id=approval.session_id,
            call_id=approval.call_id,
            payload={"approval_id": approval.approval_id, "status": status},
        )
    )
