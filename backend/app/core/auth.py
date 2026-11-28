"""FastAPI Firebase authentication and role authorization.

Production (or ``FIREBASE_AUTH_REQUIRED=true``): every request needs a valid
Firebase ID token for this project with ``email_verified == true``; the role
comes from the ``role`` custom claim (default VIEWER).

Development without Firebase: there is no implicit identity. A request must
name one of the explicitly configured ``DEV_AUTH_IDENTITIES`` in the
``X-AgentShield-Dev-User`` header, from a loopback client (unless
``DEV_AUTH_ALLOW_REMOTE=true``). Development identities are refused in
production.
"""

from enum import Enum
from typing import Callable

from fastapi import Header, HTTPException, Request, status

from .config import Settings, get_settings
from .firebase import FirebaseConfigurationError, verify_firebase_id_token

DEV_IDENTITY_HEADER = "X-AgentShield-Dev-User"
DEV_UID_PREFIX = "dev:"
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


class UserRole(str, Enum):
    ADMIN = "ADMIN"
    REVIEWER = "REVIEWER"
    VIEWER = "VIEWER"


class AuthenticatedUser:
    def __init__(self, uid: str, role: UserRole, email_verified: bool = True) -> None:
        self.uid = uid
        self.role = role
        self.email_verified = email_verified


def parse_dev_identities(raw: str) -> dict[str, UserRole]:
    identities: dict[str, UserRole] = {}
    for item in (raw or "").split(","):
        item = item.strip()
        if not item:
            continue
        uid, sep, role = item.partition(":")
        if not sep or not uid.strip():
            raise ValueError(f"Invalid DEV_AUTH_IDENTITIES entry: {item!r} (expected uid:ROLE)")
        identities[uid.strip()] = UserRole(role.strip().upper())
    return identities


def _dev_mode(settings: Settings) -> bool:
    return not settings.firebase_auth_required and settings.environment.lower() != "production"


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


def _dev_identity(settings: Settings, request: Request | None, dev_user: str | None) -> AuthenticatedUser:
    try:
        identities = parse_dev_identities(settings.dev_auth_identities)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Development identities are misconfigured.")
    if not identities:
        raise _unauthorized(
            "Authentication required. Configure Firebase, or set DEV_AUTH_IDENTITIES for local development."
        )
    if not dev_user:
        raise _unauthorized(f"{DEV_IDENTITY_HEADER} header is required in development mode.")
    role = identities.get(dev_user.strip())
    if role is None:
        raise _unauthorized("Unknown development identity.")
    if not settings.dev_auth_allow_remote:
        host = request.client.host if request is not None and request.client else None
        if host not in LOOPBACK_HOSTS:
            raise _unauthorized("Development identities are accepted only from loopback clients.")
    return AuthenticatedUser(uid=f"{DEV_UID_PREFIX}{dev_user.strip()}", role=role, email_verified=True)


def get_authenticated_user(
    request: Request = None,  # type: ignore[assignment]
    authorization: str | None = Header(default=None),
    x_agentshield_dev_user: str | None = Header(default=None),
) -> AuthenticatedUser:
    settings = get_settings()
    has_bearer = bool(authorization and authorization.lower().startswith("bearer "))

    if _dev_mode(settings) and not has_bearer:
        return _dev_identity(settings, request, x_agentshield_dev_user)

    if not has_bearer:
        raise _unauthorized("Firebase bearer token is required.")

    id_token = authorization.split(" ", 1)[1].strip()
    if not id_token:
        raise _unauthorized("Firebase bearer token is required.")

    try:
        decoded = verify_firebase_id_token(id_token)
    except FirebaseConfigurationError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service unavailable.",
        )
    except Exception:
        raise _unauthorized("Invalid or expired Firebase bearer token.")

    uid = decoded.get("uid") or decoded.get("sub")
    if not uid:
        raise _unauthorized("Firebase identity is missing.")

    if decoded.get("email_verified") is not True:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email verification is required to access protected operations.",
        )

    role_value = decoded.get("role", "VIEWER")
    try:
        role = UserRole(role_value)
    except ValueError:
        role = UserRole.VIEWER
    return AuthenticatedUser(uid=str(uid), role=role, email_verified=True)


def require_roles(*allowed_roles: UserRole) -> Callable:
    def dependency(
        request: Request,
        authorization: str | None = Header(default=None),
        x_agentshield_dev_user: str | None = Header(default=None),
    ) -> AuthenticatedUser:
        user = get_authenticated_user(request, authorization, x_agentshield_dev_user)
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role permissions.",
            )
        return user

    return dependency


def validate_auth_configuration(settings: Settings) -> None:
    """Startup checks; raises RuntimeError on unsafe configuration."""
    if settings.environment.lower() == "production" and settings.dev_auth_identities.strip():
        raise RuntimeError("DEV_AUTH_IDENTITIES must not be set in production.")
    parse_dev_identities(settings.dev_auth_identities)
