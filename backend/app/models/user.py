"""User profile Pydantic models and strict schema validation for Firestore ``users``."""

from datetime import UTC, datetime
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr, field_validator

from .enums import UserRole, UserStatus

USER_FIELDS = frozenset(
    {
        "uid",
        "email",
        "display_name",
        "role",
        "email_verified",
        "status",
        "created_at",
        "updated_at",
        "last_login_at",
    }
)

FORBIDDEN_CREDENTIAL_FIELDS = frozenset(
    {
        "password",
        "password_hash",
        "hashed_password",
        "raw_password",
        "salt",
        "secret",
        "id_token",
        "refresh_token",
        "access_token",
    }
)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_UID_RE = re.compile(r"^[^\s/]+$")


def validate_uid(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("uid must be a string.")
    cleaned = value.strip()
    if not cleaned or len(cleaned) > 128 or ".." in cleaned or not _UID_RE.match(cleaned):
        raise ValueError("uid must be a non-empty string up to 128 characters without spaces or '/'.")
    return cleaned


def validate_email(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("email must be a string.")
    cleaned = value.strip().lower()
    if not cleaned or len(cleaned) > 320 or not _EMAIL_RE.match(cleaned):
        raise ValueError("email must be a valid email address.")
    return cleaned


def validate_display_name(value: Any) -> str:
    if value is None:
        raise ValueError("display_name must be a string, not null.")
    if not isinstance(value, str):
        raise ValueError("display_name must be a string.")
    cleaned = value.strip()
    if len(cleaned) > 200:
        raise ValueError("display_name must be 200 characters or fewer.")
    return cleaned


def validate_role(value: Any) -> UserRole:
    if isinstance(value, UserRole):
        return value
    if not isinstance(value, str):
        raise ValueError("role must be a string.")
    try:
        return UserRole(value)
    except ValueError as exc:
        allowed = ", ".join(r.value for r in UserRole)
        raise ValueError(f"role must be one of: {allowed}.") from exc


def validate_status(value: Any) -> UserStatus:
    if isinstance(value, UserStatus):
        return value
    if not isinstance(value, str):
        raise ValueError("status must be a string.")
    try:
        return UserStatus(value)
    except ValueError as exc:
        allowed = ", ".join(s.value for s in UserStatus)
        raise ValueError(f"status must be one of: {allowed}.") from exc


def validate_email_verified(value: Any) -> bool:
    if not isinstance(value, bool):
        raise ValueError("email_verified must be a boolean.")
    return value


def validate_timestamp(value: Any, *, field_name: str, allow_none: bool = False) -> datetime | None:
    if value is None:
        if allow_none:
            return None
        raise ValueError(f"{field_name} must be a timestamp, not null.")
    if isinstance(value, bool) or not isinstance(value, datetime):
        raise ValueError(f"{field_name} must be a timestamp.")
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class UserProfile(BaseModel):
    """Canonical representation of a document in the Firestore ``users`` collection."""

    model_config = ConfigDict(extra="forbid")

    uid: StrictStr
    email: StrictStr
    display_name: StrictStr = ""
    role: UserRole = UserRole.VIEWER
    email_verified: StrictBool = False
    status: UserStatus = UserStatus.ACTIVE
    created_at: datetime
    updated_at: datetime
    last_login_at: datetime | None = None

    @field_validator("uid", mode="before")
    @classmethod
    def _check_uid(cls, value: Any) -> str:
        return validate_uid(value)

    @field_validator("email", mode="before")
    @classmethod
    def _check_email(cls, value: Any) -> str:
        return validate_email(value)

    @field_validator("display_name", mode="before")
    @classmethod
    def _check_display_name(cls, value: Any) -> str:
        return validate_display_name(value)

    @field_validator("role", mode="before")
    @classmethod
    def _check_role(cls, value: Any) -> UserRole:
        return validate_role(value)

    @field_validator("email_verified", mode="before")
    @classmethod
    def _check_email_verified(cls, value: Any) -> bool:
        return validate_email_verified(value)

    @field_validator("status", mode="before")
    @classmethod
    def _check_status(cls, value: Any) -> UserStatus:
        return validate_status(value)

    @field_validator("created_at", mode="before")
    @classmethod
    def _check_created_at(cls, value: Any) -> datetime:
        result = validate_timestamp(value, field_name="created_at", allow_none=False)
        assert result is not None
        return result

    @field_validator("updated_at", mode="before")
    @classmethod
    def _check_updated_at(cls, value: Any) -> datetime:
        result = validate_timestamp(value, field_name="updated_at", allow_none=False)
        assert result is not None
        return result

    @field_validator("last_login_at", mode="before")
    @classmethod
    def _check_last_login_at(cls, value: Any) -> datetime | None:
        return validate_timestamp(value, field_name="last_login_at", allow_none=True)


class UserSyncRequest(BaseModel):
    """Client-supplied payload for registration/login/sync.

    Role, uid, email, email_verified, and status are intentionally excluded and
    forbidden so clients can never escalate privileges or spoof identity.
    """

    model_config = ConfigDict(extra="forbid")

    display_name: StrictStr | None = Field(default=None, max_length=200)

    @field_validator("display_name", mode="before")
    @classmethod
    def _check_optional_display_name(cls, value: Any) -> str | None:
        if value is None:
            return None
        return validate_display_name(value)
