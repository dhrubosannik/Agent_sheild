"""API routes for backend-only Firestore ``security_events`` ingestion and querying."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status

from ..core.auth import AuthenticatedUser, UserRole, require_roles
from ..core.config import get_settings
from ..core.firestore import FirestoreConfigurationError
from ..models.enums import SecurityDecision
from ..models.security_event import (
    SecurityEvent,
    SecurityEventCreateRequest,
    SecurityEventListResponse,
    validate_identifier,
)
from ..storage.firestore_security_event_repository import (
    FirestoreSecurityEventRepository,
    SecurityEventConflictError,
    SecurityEventDuplicateError,
    SecurityEventValidationError,
)

router = APIRouter(prefix="/api/v1/security-events", tags=["Security Events"])


def get_security_event_repository() -> FirestoreSecurityEventRepository:
    settings = get_settings()
    if settings.database_mode.lower() != "firestore":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Security events repository requires Firestore database mode.",
        )
    try:
        return FirestoreSecurityEventRepository()
    except FirestoreConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc


def get_optional_security_event_repository() -> FirestoreSecurityEventRepository | None:
    settings = get_settings()
    if settings.database_mode.lower() != "firestore":
        return None
    try:
        return FirestoreSecurityEventRepository()
    except FirestoreConfigurationError:
        return None


def _parse_utc_date_range(date_str: str) -> tuple[datetime, datetime]:
    try:
        day = datetime.strptime(date_str.strip(), "%Y-%m-%d").replace(tzinfo=UTC)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="date must be in YYYY-MM-DD format.",
        ) from exc
    return day, day + timedelta(days=1)


@router.post("", response_model=SecurityEvent)
def create_security_event(
    payload: SecurityEventCreateRequest,
    response: Response,
    x_idempotency_key: str | None = Header(default=None),
    x_correlation_id: str | None = Header(default=None),
    repo: FirestoreSecurityEventRepository = Depends(get_security_event_repository),
    user: AuthenticatedUser = Depends(
        require_roles(UserRole.ADMIN, UserRole.REVIEWER, UserRole.VIEWER)
    ),
) -> SecurityEvent:
    """Persists a validated security event for the authenticated caller.

    Supports idempotency via ``X-Idempotency-Key`` (or matching ``event_id``):
    replaying the same idempotency key returns the existing event (HTTP 200)
    without creating duplicates or overwriting existing records; conflicting
    payloads or duplicate non-idempotent ``event_id`` writes return HTTP 409.
    """
    clean_idem_key: str | None = None
    if x_idempotency_key is not None and x_idempotency_key.strip():
        try:
            clean_idem_key = validate_identifier(
                x_idempotency_key, field_name="X-Idempotency-Key", max_length=128
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
            ) from exc

    resolved_event_id = payload.event_id or clean_idem_key
    resolved_correlation = payload.correlation_id
    if resolved_correlation is None and x_correlation_id and x_correlation_id.strip():
        try:
            resolved_correlation = validate_identifier(
                x_correlation_id, field_name="X-Correlation-ID", max_length=128
            )
        except ValueError:
            resolved_correlation = None

    try:
        event, created = repo.create_event(
            event_id=resolved_event_id,
            user_id=user.uid,
            agent_id=payload.agent_id,
            tool_name=payload.tool_name,
            decision=payload.decision,
            risk_level=payload.risk_level,
            reason=payload.reason,
            policy_id=payload.policy_id,
            correlation_id=resolved_correlation,
            metadata=payload.metadata,
            idempotent=bool(clean_idem_key),
        )
    except SecurityEventValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except (SecurityEventDuplicateError, SecurityEventConflictError) as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    response.status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK
    return event


@router.get("", response_model=SecurityEventListResponse)
def list_security_events(
    user_id: str | None = Query(default=None, max_length=128),
    decision: SecurityDecision | None = Query(default=None),
    date: str | None = Query(default=None, max_length=32),
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=100),
    cursor: str | None = Query(default=None, max_length=128),
    repo: FirestoreSecurityEventRepository = Depends(get_security_event_repository),
    user: AuthenticatedUser = Depends(
        require_roles(UserRole.ADMIN, UserRole.REVIEWER, UserRole.VIEWER)
    ),
) -> SecurityEventListResponse:
    """Lists ``security_events`` with user, decision, and date filters plus cursor pagination."""
    effective_user_id = user_id
    if user.role == UserRole.VIEWER:
        if user_id is not None and user_id != user.uid:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Viewers can only access their own security events.",
            )
        effective_user_id = user.uid

    resolved_start = start_date
    resolved_end = end_date
    if date is not None:
        if start_date is not None or end_date is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Specify either 'date' or 'start_date'/'end_date', not both.",
            )
        resolved_start, resolved_end = _parse_utc_date_range(date)

    try:
        items, total, next_cursor = repo.list_events_page(
            user_id=effective_user_id,
            decision=decision,
            start_date=resolved_start,
            end_date=resolved_end,
            limit=limit,
            cursor=cursor,
        )
    except SecurityEventValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return SecurityEventListResponse(
        items=items,
        total=total,
        limit=limit,
        next_cursor=next_cursor,
    )


@router.get("/{event_id}", response_model=SecurityEvent)
def get_security_event(
    event_id: str,
    repo: FirestoreSecurityEventRepository = Depends(get_security_event_repository),
    user: AuthenticatedUser = Depends(
        require_roles(UserRole.ADMIN, UserRole.REVIEWER, UserRole.VIEWER)
    ),
) -> SecurityEvent:
    """Retrieves a single security event by ``event_id``."""
    try:
        event = repo.get_by_id(event_id)
    except SecurityEventValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event '{event_id}' not found.",
        )
    if user.role == UserRole.VIEWER and event.user_id != user.uid:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Viewers can only access their own security events.",
        )
    return event
