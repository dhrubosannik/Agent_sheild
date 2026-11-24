"""API routes for human-in-the-loop approvals."""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field

from ..models.approval import Approval
from ..models.enums import ApprovalStatus
from ..services.audit_logger import AuditLogger, get_audit_service
from ..storage.approval_repository import (
    ApprovalConflictError,
    ApprovalNotFoundError,
)
from ..core.auth import AuthenticatedUser, UserRole, require_roles

router = APIRouter(prefix="/api/v1/approvals", tags=["Approvals"])


class ApprovalListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[Approval]
    total: int
    limit: int
    offset: int


class ApprovalDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["APPROVED", "REJECTED"]
    reviewer: str = Field(min_length=1)


@router.get("", response_model=ApprovalListResponse)
def list_approvals(
    status_filter: ApprovalStatus | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    audit_logger: AuditLogger = Depends(get_audit_service),
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN, UserRole.REVIEWER, UserRole.VIEWER)),
) -> ApprovalListResponse:
    """Retrieves paginated approval requests, optionally filtered by status (PENDING, APPROVED, REJECTED)."""
    items, total = audit_logger.list_approvals(
        status=status_filter,
        limit=limit,
        offset=offset,
    )
    return ApprovalListResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post("/{approval_id}/decision", response_model=Approval)
def review_approval(
    approval_id: str,
    payload: ApprovalDecisionRequest,
    audit_logger: AuditLogger = Depends(get_audit_service),
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN, UserRole.REVIEWER)),
) -> Approval:
    """Records an approval or rejection decision for a pending action.

    NOTE: For the MVP, reviewing an approval strictly updates the approval record;
    it does not automatically re-execute the underlying tool call.
    """
    try:
        reviewer_uid = user.uid if user.uid != "local-demo" else payload.reviewer
        updated = audit_logger.review_approval(
            approval_id=approval_id,
            decision=payload.decision,
            reviewer=reviewer_uid,
        )
        return updated
    except ApprovalNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Approval record '{approval_id}' not found.",
        )
    except ApprovalConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        )
