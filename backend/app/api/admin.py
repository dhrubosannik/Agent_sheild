"""Administrative user, role, and status management APIs."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict

from ..core.auth import AuthenticatedUser, UserRole, require_roles
from ..core.config import get_settings
from ..core.firebase import FirebaseConfigurationError, get_firebase_app
from ..core.firestore import FirestoreConfigurationError
from ..models.enums import UserStatus
from ..models.user import UserProfile, validate_uid
from ..storage.firestore_user_repository import (
    FirestoreUserRepository,
    UserNotFoundError,
    UserPermissionError,
    UserValidationError,
)

router = APIRouter(prefix="/api/v1/admin", tags=["Administration"])


class RoleAssignmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: UserRole


class StatusAssignmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: UserStatus


class UserListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[UserProfile]
    total: int
    limit: int
    next_cursor: str | None = None


def get_optional_user_repository() -> FirestoreUserRepository | None:
    settings = get_settings()
    if settings.database_mode.lower() != "firestore":
        return None
    try:
        return FirestoreUserRepository()
    except FirestoreConfigurationError:
        return None


def _require_user_repository(
    user_repo: FirestoreUserRepository | None = Depends(get_optional_user_repository),
) -> FirestoreUserRepository:
    if user_repo is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="User repository requires Firestore database mode.",
        )
    return user_repo


@router.get("/users", response_model=UserListResponse)
def list_users(
    limit: int = Query(default=50, ge=1, le=100),
    cursor: str | None = Query(default=None, max_length=128),
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN)),
    user_repo: FirestoreUserRepository = Depends(_require_user_repository),
) -> UserListResponse:
    """Lists user profiles from the Firestore ``users`` collection (ADMIN only)."""
    try:
        items, total, next_cursor = user_repo.list_users_page(limit=limit, cursor=cursor)
    except UserValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return UserListResponse(items=items, total=total, limit=limit, next_cursor=next_cursor)


@router.get("/users/{uid}", response_model=UserProfile)
def get_user(
    uid: str,
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN)),
    user_repo: FirestoreUserRepository = Depends(_require_user_repository),
) -> UserProfile:
    """Fetches a single user profile by Firebase Auth UID (ADMIN only)."""
    try:
        clean_uid = validate_uid(uid)
        profile = user_repo.get_by_uid(clean_uid)
    except (ValueError, UserValidationError) as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User '{clean_uid}' not found.")
    return profile


@router.post("/users/{uid}/role")
def assign_role(
    uid: str,
    payload: RoleAssignmentRequest,
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN)),
    user_repo: FirestoreUserRepository | None = Depends(get_optional_user_repository),
) -> dict:
    """Assigns a role in Firebase Auth custom claims and synchronizes Firestore ``users/{uid}``."""
    if payload is None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Role is required.")
    try:
        target_uid = validate_uid(uid)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    if target_uid == user.uid:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Users cannot modify their own role.",
        )

    auth_profile: dict | None = None
    try:
        app = get_firebase_app()
        if app is None:
            raise FirebaseConfigurationError("Firebase Admin is not initialized")
        from firebase_admin import auth

        try:
            auth_user = auth.get_user(target_uid, app=app)
        except auth.UserNotFoundError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Firebase user '{target_uid}' not found.",
            ) from exc

        claims = dict(auth_user.custom_claims or {})
        claims["role"] = payload.role.value
        auth.set_custom_user_claims(target_uid, claims, app=app)
        if auth_user.email:
            auth_profile = {
                "email": auth_user.email,
                "email_verified": bool(auth_user.email_verified),
                "display_name": auth_user.display_name or "",
            }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Role assignment service unavailable.",
        ) from exc

    if user_repo is not None:
        try:
            user_repo.update_role(
                uid=target_uid,
                new_role=payload.role,
                actor_uid=user.uid,
                create_if_missing_from_auth=auth_profile,
            )
        except UserPermissionError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except UserNotFoundError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        except UserValidationError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    return {
        "uid": target_uid,
        "role": payload.role.value,
        "assigned_by": user.uid,
    }


@router.post("/users/{uid}/status", response_model=UserProfile)
def assign_status(
    uid: str,
    payload: StatusAssignmentRequest,
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN)),
    user_repo: FirestoreUserRepository = Depends(_require_user_repository),
) -> UserProfile:
    """Updates a user's account status (ACTIVE, DISABLED, SUSPENDED) in Firestore."""
    try:
        target_uid = validate_uid(uid)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    if target_uid == user.uid:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrators cannot modify their own account status.",
        )

    try:
        profile = user_repo.update_status(
            uid=target_uid,
            new_status=payload.status,
            actor_uid=user.uid,
        )
    except UserPermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except UserNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except UserValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    try:
        app = get_firebase_app()
    except FirebaseConfigurationError:
        app = None
    if app is not None:
        from firebase_admin import auth

        try:
            auth.update_user(target_uid, disabled=(payload.status == UserStatus.DISABLED), app=app)
        except auth.UserNotFoundError:
            pass

    return profile
