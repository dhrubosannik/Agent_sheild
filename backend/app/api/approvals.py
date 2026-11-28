"""API routes for human-in-the-loop approvals.

Decisions are accepted only here: Firestore Security Rules deny every client
write to ``approvals``. The backend authenticates the caller, enforces the
ADMIN/REVIEWER role, records the authenticated uid as reviewer (a reviewer
name in the request body is ignored), and performs the PENDING -> APPROVED /
REJECTED / EXPIRED transition atomically together with its audit record.
"""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field

from ..core.auth import AuthenticatedUser, UserRole, require_roles
from ..core.config import get_settings
from ..models.approval import Approval
from ..models.enums import ApprovalStatus
from ..services.audit_logger import AuditLogger, get_audit_service
from ..storage.approval_repository import (
    ApprovalConflictError,
    ApprovalNotFoundError,
    ApprovalUnauthorizedError,
)
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
    decision_reason: str | None = Field(default=None, max_length=1000)
    # Deprecated and ignored: the reviewer is always the authenticated caller.
    reviewer: str | None = Field(default=None, max_length=200)


class ApprovalActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision_reason: str | None = Field(default=None, max_length=1000)


def _execute_decision(
    *,
    approval_id: str,
    decision: ApprovalStatus | str,
    decision_reason: str | None,
    audit_logger: AuditLogger,
    user: AuthenticatedUser,
) -> Approval:
    settings = get_settings()
    try:
        return audit_logger.review_approval(
            approval_id=approval_id,
            decision=decision,
            reviewer=user.uid,
            decision_reason=decision_reason,
            enforce_separation_of_duties=settings.require_approval_separation_of_duties,
        )
    except ApprovalNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Approval record '{approval_id}' not found.",
        )
    except ApprovalUnauthorizedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ApprovalConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    except AuditChainError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Audit log unavailable; decision not recorded.",
        )


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


@router.get("/pending", response_model=ApprovalListResponse)
def list_pending_approvals(
    limit: int = Query(default=50, ge=1, le=100),
    cursor: str | None = Query(default=None, max_length=200),
    audit_logger: AuditLogger = Depends(get_audit_service),
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN, UserRole.REVIEWER, UserRole.VIEWER)),
) -> ApprovalListResponse:
    """Retrieves pending approval requests (newest first) with cursor pagination."""
    try:
        items, total, next_cursor = audit_logger.list_approvals_page(
            status=ApprovalStatus.PENDING, limit=limit, offset=0, cursor=cursor
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return ApprovalListResponse(items=items, total=total, limit=limit, offset=0, next_cursor=next_cursor)


@router.get("/{approval_id}", response_model=Approval)
def get_approval(
    approval_id: str,
    audit_logger: AuditLogger = Depends(get_audit_service),
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN, UserRole.REVIEWER, UserRole.VIEWER)),
) -> Approval:
    """Retrieves a single approval record by ID."""
    approval = audit_logger.get_approval(approval_id)
    if approval is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Approval record '{approval_id}' not found.",
        )
    return approval


@router.post("/{approval_id}/decision", response_model=Approval)
def review_approval(
    approval_id: str,
    payload: ApprovalDecisionRequest,
    audit_logger: AuditLogger = Depends(get_audit_service),
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN, UserRole.REVIEWER)),
) -> Approval:
    """Records an approval or rejection decision for a pending action."""
    return _execute_decision(
        approval_id=approval_id,
        decision=payload.decision,
        decision_reason=payload.decision_reason,
        audit_logger=audit_logger,
        user=user,
    )


@router.post("/{approval_id}/approve", response_model=Approval)
def approve_request(
    approval_id: str,
    payload: ApprovalActionRequest | None = None,
    audit_logger: AuditLogger = Depends(get_audit_service),
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN, UserRole.REVIEWER)),
) -> Approval:
    """Approves a pending approval request atomically."""
    return _execute_decision(
        approval_id=approval_id,
        decision=ApprovalStatus.APPROVED,
        decision_reason=payload.decision_reason if payload else None,
        audit_logger=audit_logger,
        user=user,
    )


@router.post("/{approval_id}/reject", response_model=Approval)
def reject_request(
    approval_id: str,
    payload: ApprovalActionRequest | None = None,
    audit_logger: AuditLogger = Depends(get_audit_service),
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN, UserRole.REVIEWER)),
) -> Approval:
    """Rejects a pending approval request atomically."""
    return _execute_decision(
        approval_id=approval_id,
        decision=ApprovalStatus.REJECTED,
        decision_reason=payload.decision_reason if payload else None,
        audit_logger=audit_logger,
        user=user,
    )
