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


@router.get("", response_model=EventListResponse)
def list_audit_events(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    decision: SecurityDecision | None = Query(default=None),
    tool_name: str | None = Query(default=None),
    audit_logger: AuditLogger = Depends(get_audit_service),
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN, UserRole.REVIEWER, UserRole.VIEWER)),
) -> EventListResponse:
    """Retrieves paginated audit events with optional filtering by decision or tool name."""
    items, total = audit_logger.list_events(
        limit=limit,
        offset=offset,
        decision=decision,
        tool_name=tool_name,
    )
    return EventListResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
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
