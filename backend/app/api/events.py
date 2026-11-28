"""API routes for querying audit events."""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict

from ..models.audit_event import AuditEvent
from ..models.enums import SecurityDecision
from ..services.audit_logger import AuditLogger, get_audit_service
from ..core.auth import AuthenticatedUser, UserRole, require_roles

router = APIRouter(prefix="/api/v1/events", tags=["Audit Events"])


class EventListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[AuditEvent]
    total: int
    limit: int
    offset: int
    next_cursor: str | None = None


@router.get("", response_model=EventListResponse)
def list_audit_events(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=1000),
    decision: SecurityDecision | None = Query(default=None),
    tool_name: str | None = Query(default=None, max_length=200),
    cursor: str | None = Query(default=None, max_length=200),
    audit_logger: AuditLogger = Depends(get_audit_service),
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN, UserRole.REVIEWER, UserRole.VIEWER)),
) -> EventListResponse:
    """Paginated DECISION audit events (newest first). Pass ``next_cursor``
    back as ``cursor`` for the next page."""
    try:
        items, total, next_cursor = audit_logger.list_events_page(
            limit=limit,
            offset=offset,
            decision=decision,
            tool_name=tool_name,
            cursor=cursor,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return EventListResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        next_cursor=next_cursor,
    )


@router.get("/{event_id}", response_model=AuditEvent)
def get_audit_event(
    event_id: str,
    audit_logger: AuditLogger = Depends(get_audit_service),
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN, UserRole.REVIEWER, UserRole.VIEWER)),
) -> AuditEvent:
    """Retrieves a single audit event by its unique ID. Returns 404 if not found."""
    event = audit_logger.get_event(event_id)
    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit event '{event_id}' not found.",
        )
    return event
