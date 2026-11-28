"""Authenticated user profile registration, login, and Auth sync APIs."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status

from ..core.auth import AuthenticatedUser, get_firebase_session_user
from ..core.config import get_settings
from ..core.firebase import FirebaseConfigurationError, get_firebase_app
from ..core.firestore import FirestoreConfigurationError
from ..models.user import UserProfile, UserSyncRequest
from ..storage.firestore_user_repository import (
    FirestoreUserRepository,
    UserDisabledError,
    UserValidationError,
)

router = APIRouter(prefix="/api/v1/users", tags=["Users"])


def get_user_repository() -> FirestoreUserRepository:
    settings = get_settings()
    if settings.database_mode.lower() != "firestore":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="User repository requires Firestore database mode.",
        )
    try:
        return FirestoreUserRepository()
    except FirestoreConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc


def _resolve_auth_identity(
    session_user: AuthenticatedUser,
    requested_display_name: str | None = None,
) -> tuple[str, bool, str]:
    """Resolves authoritative email, email_verified, and display_name from Firebase Auth."""
    email = session_user.email
    email_verified = bool(session_user.email_verified)
    auth_display_name = session_user.display_name or ""

    try:
        app = get_firebase_app()
    except FirebaseConfigurationError:
        app = None

    if app is not None:
        from firebase_admin import auth

        try:
            auth_user = auth.get_user(session_user.uid, app=app)
        except auth.UserNotFoundError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Firebase user record not found.",
            ) from exc
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service unavailable.",
            ) from exc

        if auth_user.disabled:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is disabled.",
            )
        email = auth_user.email or email
        email_verified = bool(auth_user.email_verified)
        auth_display_name = auth_user.display_name or auth_display_name

    if not email:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Authenticated user does not have an email address.",
        )

    display_name = requested_display_name if requested_display_name is not None else auth_display_name
    return email, email_verified, display_name


@router.post("/register", response_model=UserProfile)
def register_user_profile(
    response: Response,
    payload: UserSyncRequest | None = None,
    session_user: AuthenticatedUser = Depends(get_firebase_session_user),
    user_repo: FirestoreUserRepository = Depends(get_user_repository),
) -> UserProfile:
    """Creates a ``users/{uid}`` profile with default VIEWER role after registration.

    Never overwrites an existing user record and never accepts client-supplied roles.
    """
    requested_name = payload.display_name if payload else None
    email, email_verified, display_name = _resolve_auth_identity(session_user, requested_name)
    try:
        profile, created = user_repo.create_user_on_registration(
            uid=session_user.uid,
            email=email,
            display_name=display_name,
            email_verified=email_verified,
        )
    except UserValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    response.status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK
    return profile


@router.post("/login", response_model=UserProfile)
def record_user_login(
    payload: UserSyncRequest | None = None,
    session_user: AuthenticatedUser = Depends(get_firebase_session_user),
    user_repo: FirestoreUserRepository = Depends(get_user_repository),
) -> UserProfile:
    """Synchronizes Firebase Auth email/verification state and updates ``last_login_at``."""
    requested_name = payload.display_name if payload else None
    email, email_verified, display_name = _resolve_auth_identity(session_user, requested_name)
    try:
        return user_repo.sync_from_auth(
            uid=session_user.uid,
            email=email,
            email_verified=email_verified,
            display_name=display_name or None,
            mark_login=True,
        )
    except UserDisabledError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except UserValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc


@router.post("/sync", response_model=UserProfile)
def sync_user_profile(
    payload: UserSyncRequest | None = None,
    session_user: AuthenticatedUser = Depends(get_firebase_session_user),
    user_repo: FirestoreUserRepository = Depends(get_user_repository),
) -> UserProfile:
    """Synchronizes email and ``email_verified`` from Firebase Authentication."""
    requested_name = payload.display_name if payload else None
    email, email_verified, display_name = _resolve_auth_identity(session_user, requested_name)
    try:
        return user_repo.sync_from_auth(
            uid=session_user.uid,
            email=email,
            email_verified=email_verified,
            display_name=display_name or None,
            mark_login=False,
        )
    except UserDisabledError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except UserValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc


@router.get("/me", response_model=UserProfile)
def get_my_profile(
    session_user: AuthenticatedUser = Depends(get_firebase_session_user),
    user_repo: FirestoreUserRepository = Depends(get_user_repository),
) -> UserProfile:
    """Returns the authenticated user's Firestore profile."""
    try:
        profile = user_repo.get_by_uid(session_user.uid)
    except UserValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User profile not found.")
    return profile
