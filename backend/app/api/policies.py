"""Policy configuration and Firestore ``policies`` management API."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, ConfigDict

from ..core.auth import AuthenticatedUser, UserRole, require_roles
from ..core.config import get_settings
from ..core.firestore import FirestoreConfigurationError
from ..core.policy_loader import load_active_policy, load_policy
from ..models.enums import SecurityDecision
from ..models.policy import (
    PolicyCreateRequest,
    PolicyHistoryEntry,
    PolicyListResponse,
    PolicyUpdateRequest,
    StoredPolicy,
    validate_policy_id,
)
from ..storage.firestore_policy_repository import (
    FirestorePolicyRepository,
    PolicyAlreadyExistsError,
    PolicyNotFoundError,
    StoredPolicyValidationError,
)

router = APIRouter(prefix="/api/v1/policies", tags=["Policies"])


class ProtectedRuleView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    action: SecurityDecision


class PolicyRuleView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    description: str
    tools: list[str]
    data_labels: list[str]
    destination_classes: list[str]
    decision: SecurityDecision


class PolicyView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int
    approved_domains: list[str]
    protected_values: list[ProtectedRuleView]
    rules: list[PolicyRuleView]


def get_policy_repository() -> FirestorePolicyRepository:
    settings = get_settings()
    if settings.database_mode.lower() != "firestore":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Policy repository requires Firestore database mode.",
        )
    try:
        return FirestorePolicyRepository()
    except FirestoreConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc


def get_optional_policy_repository() -> FirestorePolicyRepository | None:
    settings = get_settings()
    if settings.database_mode.lower() != "firestore":
        return None
    try:
        return FirestorePolicyRepository()
    except FirestoreConfigurationError:
        return None


@router.get("/current", response_model=PolicyView)
def get_current_policy(
    policy_repo: FirestorePolicyRepository | None = Depends(get_optional_policy_repository),
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN, UserRole.REVIEWER, UserRole.VIEWER)),
) -> PolicyView:
    policy = load_active_policy(policy_repo=policy_repo) if policy_repo is not None else load_policy()
    return PolicyView(
        version=policy.version,
        approved_domains=policy.approved_domains,
        protected_values=[
            ProtectedRuleView(name=item.name, action=item.action)
            for item in policy.protected_values
        ],
        rules=[
            PolicyRuleView(
                id=rule.id,
                description=rule.description,
                tools=rule.tools,
                data_labels=rule.data_labels,
                destination_classes=[item.value for item in rule.destination_classes],
                decision=rule.decision,
            )
            for rule in policy.rules
        ],
    )


@router.get("", response_model=PolicyListResponse)
def list_policies(
    enabled: bool | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=100),
    cursor: str | None = Query(default=None, max_length=128),
    policy_repo: FirestorePolicyRepository = Depends(get_policy_repository),
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN, UserRole.REVIEWER, UserRole.VIEWER)),
) -> PolicyListResponse:
    """Lists stored Firestore policies ordered by ascending priority."""
    try:
        items, total, next_cursor = policy_repo.list_policies_page(
            enabled=enabled, limit=limit, cursor=cursor
        )
    except StoredPolicyValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return PolicyListResponse(items=items, total=total, limit=limit, next_cursor=next_cursor)


@router.get("/{policy_id}", response_model=StoredPolicy)
def get_policy(
    policy_id: str,
    policy_repo: FirestorePolicyRepository = Depends(get_policy_repository),
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN, UserRole.REVIEWER, UserRole.VIEWER)),
) -> StoredPolicy:
    """Retrieves a single stored policy by ``policy_id``."""
    try:
        clean_id = validate_policy_id(policy_id)
        policy = policy_repo.get_by_id(clean_id)
    except (ValueError, StoredPolicyValidationError) as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    if policy is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Policy '{clean_id}' not found.")
    return policy


@router.get("/{policy_id}/history", response_model=list[PolicyHistoryEntry])
def get_policy_history(
    policy_id: str,
    policy_repo: FirestorePolicyRepository = Depends(get_policy_repository),
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN)),
) -> list[PolicyHistoryEntry]:
    """Returns the immutable versioned change history for a policy (ADMIN only)."""
    try:
        clean_id = validate_policy_id(policy_id)
        if policy_repo.get_by_id(clean_id) is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Policy '{clean_id}' not found.")
        return policy_repo.list_history(clean_id)
    except HTTPException:
        raise
    except (ValueError, StoredPolicyValidationError) as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc


@router.post("", response_model=StoredPolicy, status_code=status.HTTP_201_CREATED)
def create_policy(
    payload: PolicyCreateRequest,
    response: Response,
    policy_repo: FirestorePolicyRepository = Depends(get_policy_repository),
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN)),
) -> StoredPolicy:
    """Creates a new policy in Firestore ``policies/{policy_id}`` (ADMIN only)."""
    try:
        created = policy_repo.create_policy(
            policy_id=payload.policy_id,
            name=payload.name,
            description=payload.description,
            enabled=payload.enabled,
            priority=payload.priority,
            action=payload.action,
            rules=payload.rules,
            created_by=user.uid,
        )
    except PolicyAlreadyExistsError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except StoredPolicyValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    response.status_code = status.HTTP_201_CREATED
    return created


@router.post("/{policy_id}/update", response_model=StoredPolicy)
def update_policy(
    policy_id: str,
    payload: PolicyUpdateRequest,
    policy_repo: FirestorePolicyRepository = Depends(get_policy_repository),
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN)),
) -> StoredPolicy:
    """Updates an existing policy and increments ``version`` atomically (ADMIN only)."""
    try:
        return policy_repo.update_policy(
            policy_id,
            updated_by=user.uid,
            name=payload.name,
            description=payload.description,
            enabled=payload.enabled,
            priority=payload.priority,
            action=payload.action,
            rules=payload.rules,
        )
    except PolicyNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except StoredPolicyValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc


@router.post("/{policy_id}/enable", response_model=StoredPolicy)
def enable_policy(
    policy_id: str,
    policy_repo: FirestorePolicyRepository = Depends(get_policy_repository),
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN)),
) -> StoredPolicy:
    """Enables a policy and increments ``version`` atomically (ADMIN only)."""
    try:
        return policy_repo.set_enabled(policy_id, enabled=True, updated_by=user.uid)
    except PolicyNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except StoredPolicyValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc


@router.post("/{policy_id}/disable", response_model=StoredPolicy)
def disable_policy(
    policy_id: str,
    policy_repo: FirestorePolicyRepository = Depends(get_policy_repository),
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN)),
) -> StoredPolicy:
    """Disables a policy and increments ``version`` atomically (ADMIN only)."""
    try:
        return policy_repo.set_enabled(policy_id, enabled=False, updated_by=user.uid)
    except PolicyNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except StoredPolicyValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
