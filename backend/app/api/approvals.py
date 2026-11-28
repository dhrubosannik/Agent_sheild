"""API routes for human-in-the-loop approvals.

Decisions are accepted only here: Firestore Security Rules deny every client
write to ``approvals``. The backend authenticates the caller, enforces the
ADMIN/REVIEWER role, records the authenticated uid as reviewer (a reviewer
name in the request body is ignored), and performs the PENDING -> APPROVED /
REJECTED transition atomically together with its audit record.
"""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field

from ..core.auth import AuthenticatedUser, UserRole, require_roles
from ..models.approval import Approval
from ..models.enums import ApprovalStatus
from ..services.audit_logger import AuditLogger, get_audit_service
from ..storage.approval_repository import ApprovalConflictError, ApprovalNotFoundError
from ..storage.audit_repository import AuditChainError

router = APIRouter(prefix="/api/v1/approvals", tags=["Approvals"])


class ApprovalListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[Approval]
    total: int
    limit: int
    offset: int
    next_cursor: str | None = None


class ApprovalDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["APPROVED", "REJECTED"]
    # Deprecated and ignored: the reviewer is always the authenticated caller.
    reviewer: str | None = Field(default=None, max_length=200)


@router.get("", response_model=ApprovalListResponse)
def list_approvals(
    status_filter: ApprovalStatus | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=1000),
    cursor: str | None = Query(default=None, max_length=200),
    audit_logger: AuditLogger = Depends(get_audit_service),
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN, UserRole.REVIEWER, UserRole.VIEWER)),
) -> ApprovalListResponse:
    """Paginated approval requests (newest first). Pass ``next_cursor`` back as
    ``cursor`` for the next page."""
    try:
        items, total, next_cursor = audit_logger.list_approvals_page(
            status=status_filter, limit=limit, offset=offset, cursor=cursor
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return ApprovalListResponse(items=items, total=total, limit=limit, offset=offset, next_cursor=next_cursor)


@router.post("/{approval_id}/decision", response_model=Approval)
def review_approval(
    approval_id: str,
    payload: ApprovalDecisionRequest,
    audit_logger: AuditLogger = Depends(get_audit_service),
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN, UserRole.REVIEWER)),
) -> Approval:
    """Records an approval or rejection decision for a pending action.

    NOTE: Reviewing an approval updates the approval record and appends an
    APPROVAL_DECISION audit record; it does not re-execute the tool call.
    """
    try:
        return audit_logger.review_approval(
            approval_id=approval_id,
            decision=payload.decision,
            reviewer=user.uid,
        )
    except ApprovalNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Approval record '{approval_id}' not found.",
        )
    except ApprovalConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except AuditChainError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Audit log unavailable; decision not recorded.",
        )
