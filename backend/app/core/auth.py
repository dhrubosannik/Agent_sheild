"""FastAPI Firebase authentication and role authorization."""

from enum import Enum
from typing import Callable

from fastapi import Header, HTTPException, status

from .config import get_settings
from .firebase import FirebaseConfigurationError, verify_firebase_id_token


class UserRole(str, Enum):
    ADMIN = "ADMIN"
    REVIEWER = "REVIEWER"
    VIEWER = "VIEWER"


class AuthenticatedUser:
    def __init__(self, uid: str, role: UserRole, email_verified: bool = True) -> None:
        self.uid = uid
        self.role = role
        self.email_verified = email_verified


def get_authenticated_user(
    authorization: str | None = Header(default=None),
) -> AuthenticatedUser:
    settings = get_settings()
    if (
        not settings.firebase_auth_required
        and settings.environment.lower() != "production"
    ):
        return AuthenticatedUser(uid="local-demo", role=UserRole.ADMIN, email_verified=True)

    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Firebase bearer token is required.",
        )

    id_token = authorization.split(" ", 1)[1].strip()
    if not id_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Firebase bearer token is required.",
        )

    try:
        decoded = verify_firebase_id_token(id_token)
    except FirebaseConfigurationError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service unavailable.",
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired Firebase bearer token.",
        )

    uid = decoded.get("uid") or decoded.get("sub")
    if not uid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Firebase identity is missing.",
        )

    email_verified = bool(decoded.get("email_verified", False))
    if not email_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email verification is required to access protected operations.",
        )

    role_value = decoded.get("role", "VIEWER")
    try:
        role = UserRole(role_value)
    except ValueError:
        role = UserRole.VIEWER
    return AuthenticatedUser(uid=str(uid), role=role, email_verified=email_verified)


def require_roles(*allowed_roles: UserRole) -> Callable:
    def dependency(
        authorization: str | None = Header(default=None),
    ) -> AuthenticatedUser:
        user = get_authenticated_user(authorization)
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role permissions.",
            )
        return user

    return dependency
