"""Cloud Firestore user profile repository for the ``users`` collection.

Documents are keyed by Firebase Authentication UID (``users/{uid}``).
All client SDK writes are denied in ``firestore.rules``; every write flows
through this backend repository using the Firebase Admin SDK so field types,
allowed roles/statuses, server timestamps, and role-escalation protections are
enforced server-side.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from google.cloud import firestore
from google.cloud.firestore_v1.base_query import FieldFilter

from ..core.firestore import get_firestore_client
from ..models.enums import UserRole, UserStatus
from ..models.user import (
    FORBIDDEN_CREDENTIAL_FIELDS,
    USER_FIELDS,
    UserProfile,
    validate_display_name,
    validate_email,
    validate_email_verified,
    validate_role,
    validate_status,
    validate_uid,
)

USERS = "users"
MAX_LIMIT = 100


class UserNotFoundError(Exception):
    """Raised when a requested user document does not exist."""


class UserAlreadyExistsError(Exception):
    """Raised when creating a user document that already exists."""


class UserValidationError(ValueError):
    """Raised when user data fails schema or security validation."""


class UserPermissionError(PermissionError):
    """Raised on unauthorized role or status modification attempts."""


class UserDisabledError(PermissionError):
    """Raised when a DISABLED or SUSPENDED user attempts to log in."""


def _is_server_timestamp(value: Any) -> bool:
    return value is firestore.SERVER_TIMESTAMP


def _validate_write_dict(data: dict[str, Any], *, partial: bool = False) -> None:
    forbidden = FORBIDDEN_CREDENTIAL_FIELDS.intersection(data.keys())
    if forbidden:
        raise UserValidationError(
            f"Forbidden credential fields cannot be stored in Firestore: {sorted(forbidden)}"
        )
    unknown = set(data.keys()) - USER_FIELDS
    if unknown:
        raise UserValidationError(f"Unknown user fields are not allowed: {sorted(unknown)}")
    if not partial and set(data.keys()) != USER_FIELDS:
        missing = sorted(USER_FIELDS - set(data.keys()))
        raise UserValidationError(f"Missing required user fields: {missing}")

    if "uid" in data:
        validate_uid(data["uid"])
    if "email" in data:
        validate_email(data["email"])
    if "display_name" in data:
        validate_display_name(data["display_name"])
    if "role" in data:
        validate_role(data["role"])
    if "email_verified" in data:
        validate_email_verified(data["email_verified"])
    if "status" in data:
        validate_status(data["status"])
    for ts_field in ("created_at", "updated_at"):
        if ts_field in data:
            val = data[ts_field]
            if not (_is_server_timestamp(val) or (isinstance(val, datetime) and not isinstance(val, bool))):
                raise UserValidationError(f"{ts_field} must be a Firestore timestamp.")
    if "last_login_at" in data:
        val = data["last_login_at"]
        if val is not None and not (
            _is_server_timestamp(val) or (isinstance(val, datetime) and not isinstance(val, bool))
        ):
            raise UserValidationError("last_login_at must be a Firestore timestamp or null.")


class FirestoreUserRepository:
    """Backend repository managing ``users/{uid}`` documents in Cloud Firestore."""

    def __init__(self, client: Any | None = None) -> None:
        self.client = client or get_firestore_client()

    def _doc_ref(self, uid: str) -> Any:
        try:
            clean_uid = validate_uid(uid)
        except ValueError as exc:
            raise UserValidationError(str(exc)) from exc
        return self.client.collection(USERS).document(clean_uid)

    def _from_document(self, data: dict[str, Any]) -> UserProfile:
        if not isinstance(data, dict):
            raise UserValidationError("User document must be a mapping.")
        forbidden = FORBIDDEN_CREDENTIAL_FIELDS.intersection(data.keys())
        if forbidden:
            raise UserValidationError(
                f"User document contains forbidden credential fields: {sorted(forbidden)}"
            )
        try:
            return UserProfile.model_validate(data)
        except Exception as exc:
            raise UserValidationError(f"Invalid user document schema: {exc}") from exc

    def _build_new_document(
        self,
        *,
        uid: str,
        email: str,
        display_name: str,
        role: UserRole,
        email_verified: bool,
        status: UserStatus,
        mark_login: bool,
    ) -> dict[str, Any]:
        try:
            clean_uid = validate_uid(uid)
            clean_email = validate_email(email)
            clean_name = validate_display_name(display_name)
            valid_role = validate_role(role)
            valid_verified = validate_email_verified(email_verified)
            valid_status = validate_status(status)
        except ValueError as exc:
            raise UserValidationError(str(exc)) from exc

        doc = {
            "uid": clean_uid,
            "email": clean_email,
            "display_name": clean_name,
            "role": valid_role.value,
            "email_verified": valid_verified,
            "status": valid_status.value,
            "created_at": firestore.SERVER_TIMESTAMP,
            "updated_at": firestore.SERVER_TIMESTAMP,
            "last_login_at": firestore.SERVER_TIMESTAMP if mark_login else None,
        }
        _validate_write_dict(doc, partial=False)
        return doc

    def get_by_uid(self, uid: str) -> UserProfile | None:
        snapshot = self._doc_ref(uid).get()
        if not snapshot.exists:
            return None
        return self._from_document(snapshot.to_dict())

    def get_by_email(self, email: str) -> UserProfile | None:
        try:
            clean_email = validate_email(email)
        except ValueError as exc:
            raise UserValidationError(str(exc)) from exc
        docs = list(
            self.client.collection(USERS)
            .where(filter=FieldFilter("email", "==", clean_email))
            .limit(1)
            .stream()
        )
        return self._from_document(docs[0].to_dict()) if docs else None

    def list_users_page(
        self,
        limit: int = 50,
        cursor: str | None = None,
    ) -> tuple[list[UserProfile], int, str | None]:
        bounded_limit = max(1, min(int(limit), MAX_LIMIT))
        base = self.client.collection(USERS)
        total = int(base.count().get()[0][0].value)
        query = base.order_by("created_at", direction=firestore.Query.DESCENDING)
        if cursor:
            anchor = self._doc_ref(cursor).get()
            if not anchor.exists:
                raise UserValidationError("Invalid pagination cursor.")
            query = query.start_after(anchor)
        docs = list(query.limit(bounded_limit).stream())
        items = [self._from_document(doc.to_dict()) for doc in docs]
        next_cursor = docs[-1].id if len(docs) == bounded_limit else None
        return items, total, next_cursor

    def create_user(
        self,
        *,
        uid: str,
        email: str,
        display_name: str = "",
        email_verified: bool = False,
        status: UserStatus = UserStatus.ACTIVE,
        role: UserRole = UserRole.VIEWER,
    ) -> UserProfile:
        """Creates a new user document; fails if ``users/{uid}`` already exists."""
        doc_data = self._build_new_document(
            uid=uid,
            email=email,
            display_name=display_name,
            role=role,
            email_verified=email_verified,
            status=status,
            mark_login=False,
        )
        ref = self._doc_ref(uid)
        try:
            ref.create(doc_data)
        except Exception as exc:
            if "AlreadyExists" in type(exc).__name__ or "already exists" in str(exc).lower():
                raise UserAlreadyExistsError(f"User '{uid}' already exists.") from exc
            raise
        snapshot = ref.get()
        return self._from_document(snapshot.to_dict())

    def create_user_on_registration(
        self,
        *,
        uid: str,
        email: str,
        display_name: str = "",
        email_verified: bool = False,
    ) -> tuple[UserProfile, bool]:
        """Creates a user profile with default VIEWER role after registration.

        Never overwrites an existing user record: if ``users/{uid}`` already
        exists, returns the existing profile untouched and ``created=False``.
        """
        doc_data = self._build_new_document(
            uid=uid,
            email=email,
            display_name=display_name,
            role=UserRole.VIEWER,
            email_verified=email_verified,
            status=UserStatus.ACTIVE,
            mark_login=False,
        )
        ref = self._doc_ref(uid)

        @firestore.transactional
        def _register_tx(transaction: Any) -> bool:
            snapshot = ref.get(transaction=transaction)
            if snapshot.exists:
                return False
            transaction.create(ref, doc_data)
            return True

        created = _register_tx(self.client.transaction())
        snapshot = ref.get()
        return self._from_document(snapshot.to_dict()), created

    def sync_from_auth(
        self,
        *,
        uid: str,
        email: str,
        email_verified: bool,
        display_name: str | None = None,
        mark_login: bool = False,
    ) -> UserProfile:
        """Synchronizes email & verification status from Firebase Auth.

        - If no profile exists yet (e.g. legacy Auth user), initializes one
          with ``role="VIEWER"`` and ``status="ACTIVE"`` without trusting any
          client-supplied role.
        - If a profile exists, preserves ``uid``, ``role``, ``status``, and
          ``created_at``, updating only synchronized auth fields,
          ``updated_at``, and (when ``mark_login=True``) ``last_login_at``.
        """
        try:
            clean_uid = validate_uid(uid)
            clean_email = validate_email(email)
            valid_verified = validate_email_verified(email_verified)
            clean_name = validate_display_name(display_name) if display_name is not None else None
        except ValueError as exc:
            raise UserValidationError(str(exc)) from exc

        ref = self._doc_ref(clean_uid)

        @firestore.transactional
        def _sync_tx(transaction: Any) -> None:
            snapshot = ref.get(transaction=transaction)
            if not snapshot.exists:
                new_doc = self._build_new_document(
                    uid=clean_uid,
                    email=clean_email,
                    display_name=clean_name or "",
                    role=UserRole.VIEWER,
                    email_verified=valid_verified,
                    status=UserStatus.ACTIVE,
                    mark_login=mark_login,
                )
                transaction.create(ref, new_doc)
                return

            existing = self._from_document(snapshot.to_dict())
            if mark_login and existing.status != UserStatus.ACTIVE:
                raise UserDisabledError(f"User account is {existing.status.value}.")

            updates: dict[str, Any] = {}
            if existing.email != clean_email:
                updates["email"] = clean_email
            if existing.email_verified != valid_verified:
                updates["email_verified"] = valid_verified
            if clean_name is not None and clean_name and existing.display_name != clean_name:
                updates["display_name"] = clean_name
            if mark_login:
                updates["last_login_at"] = firestore.SERVER_TIMESTAMP

            if updates:
                updates["updated_at"] = firestore.SERVER_TIMESTAMP
                _validate_write_dict(updates, partial=True)
                transaction.update(ref, updates)

        _sync_tx(self.client.transaction())
        snapshot = ref.get()
        return self._from_document(snapshot.to_dict())

    def update_role(
        self,
        *,
        uid: str,
        new_role: UserRole | str,
        actor_uid: str,
        create_if_missing_from_auth: dict[str, Any] | None = None,
    ) -> UserProfile:
        """Updates a user's role in Firestore (admin backend operation only)."""
        try:
            target_uid = validate_uid(uid)
            admin_uid = validate_uid(actor_uid)
            role_enum = validate_role(new_role)
        except ValueError as exc:
            raise UserValidationError(str(exc)) from exc

        if target_uid == admin_uid:
            raise UserPermissionError("Users cannot modify their own role.")

        ref = self._doc_ref(target_uid)

        @firestore.transactional
        def _role_tx(transaction: Any) -> None:
            snapshot = ref.get(transaction=transaction)
            if not snapshot.exists:
                if create_if_missing_from_auth is None:
                    raise UserNotFoundError(f"User '{target_uid}' not found.")
                new_doc = self._build_new_document(
                    uid=target_uid,
                    email=create_if_missing_from_auth["email"],
                    display_name=create_if_missing_from_auth.get("display_name") or "",
                    role=role_enum,
                    email_verified=bool(create_if_missing_from_auth.get("email_verified", False)),
                    status=UserStatus.ACTIVE,
                    mark_login=False,
                )
                transaction.create(ref, new_doc)
                return

            self._from_document(snapshot.to_dict())
            updates = {
                "role": role_enum.value,
                "updated_at": firestore.SERVER_TIMESTAMP,
            }
            _validate_write_dict(updates, partial=True)
            transaction.update(ref, updates)

        _role_tx(self.client.transaction())
        snapshot = ref.get()
        return self._from_document(snapshot.to_dict())

    def update_status(
        self,
        *,
        uid: str,
        new_status: UserStatus | str,
        actor_uid: str,
    ) -> UserProfile:
        """Updates a user's account status (ACTIVE, DISABLED, SUSPENDED)."""
        try:
            target_uid = validate_uid(uid)
            admin_uid = validate_uid(actor_uid)
            status_enum = validate_status(new_status)
        except ValueError as exc:
            raise UserValidationError(str(exc)) from exc

        if target_uid == admin_uid:
            raise UserPermissionError("Administrators cannot modify their own account status.")

        ref = self._doc_ref(target_uid)

        @firestore.transactional
        def _status_tx(transaction: Any) -> None:
            snapshot = ref.get(transaction=transaction)
            if not snapshot.exists:
                raise UserNotFoundError(f"User '{target_uid}' not found.")
            self._from_document(snapshot.to_dict())
            updates = {
                "status": status_enum.value,
                "updated_at": firestore.SERVER_TIMESTAMP,
            }
            _validate_write_dict(updates, partial=True)
            transaction.update(ref, updates)

        _status_tx(self.client.transaction())
        snapshot = ref.get()
        return self._from_document(snapshot.to_dict())
