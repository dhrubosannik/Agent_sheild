"""Tests for Firestore ``users`` collection model, repository, and APIs."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

from fastapi.testclient import TestClient
from google.cloud import firestore
import pytest

from backend.app.api import admin as admin_api
from backend.app.api import users as users_api
from backend.app.core import auth as auth_module
from backend.app.main import app
from backend.app.models.enums import UserRole, UserStatus
from backend.app.models.user import UserProfile
from backend.app.storage.firestore_user_repository import (
    FirestoreUserRepository,
    UserAlreadyExistsError,
    UserDisabledError,
    UserNotFoundError,
    UserPermissionError,
    UserValidationError,
)


class _FakeSnapshot:
    def __init__(self, doc_id: str, data: dict[str, Any] | None) -> None:
        self.id = doc_id
        self._data = deepcopy(data) if data is not None else None

    @property
    def exists(self) -> bool:
        return self._data is not None

    def to_dict(self) -> dict[str, Any] | None:
        return deepcopy(self._data) if self._data is not None else None


class _FakeClock:
    def __init__(self) -> None:
        self.current = datetime(2026, 11, 28, 12, 0, 0, tzinfo=UTC)

    def tick(self) -> datetime:
        self.current = self.current + timedelta(seconds=1)
        return self.current


class _FakeDocumentRef:
    def __init__(self, store: dict[str, dict[str, Any]], doc_id: str, clock: _FakeClock) -> None:
        self._store = store
        self.id = doc_id
        self._clock = clock

    def _materialize(self, payload: dict[str, Any]) -> dict[str, Any]:
        now = self._clock.tick()
        out: dict[str, Any] = {}
        for k, v in payload.items():
            out[k] = now if v is firestore.SERVER_TIMESTAMP else deepcopy(v)
        return out

    def get(self, transaction: Any | None = None) -> _FakeSnapshot:
        return _FakeSnapshot(self.id, self._store.get(self.id))

    def create(self, data: dict[str, Any]) -> None:
        if self.id in self._store:
            raise RuntimeError("409 Document already exists")
        self._store[self.id] = self._materialize(data)

    def update(self, data: dict[str, Any]) -> None:
        if self.id not in self._store:
            raise RuntimeError("404 Document not found")
        merged = dict(self._store[self.id])
        merged.update(self._materialize(data))
        self._store[self.id] = merged


class _FakeCountQuery:
    def __init__(self, count_value: int) -> None:
        self._count_value = count_value

    def get(self):
        return [[SimpleNamespace(value=self._count_value)]]


class _FakeQuery:
    def __init__(
        self,
        store: dict[str, dict[str, Any]],
        clock: _FakeClock,
        filters: list[tuple[str, str, Any]] | None = None,
        order_field: str | None = None,
        descending: bool = False,
        after_id: str | None = None,
        limit_val: int | None = None,
    ) -> None:
        self._store = store
        self._clock = clock
        self._filters = filters or []
        self._order_field = order_field
        self._descending = descending
        self._after_id = after_id
        self._limit_val = limit_val

    def _matching_items(self) -> list[tuple[str, dict[str, Any]]]:
        items = list(self._store.items())
        for field, op, val in self._filters:
            if op == "==":
                items = [(k, d) for k, d in items if d.get(field) == val]
        if self._order_field:
            items.sort(key=lambda pair: pair[1].get(self._order_field), reverse=self._descending)
        if self._after_id is not None:
            idx = next((i for i, (k, _) in enumerate(items) if k == self._after_id), None)
            if idx is not None:
                items = items[idx + 1 :]
        if self._limit_val is not None:
            items = items[: self._limit_val]
        return items

    def where(self, *, filter: Any) -> "_FakeQuery":
        return _FakeQuery(
            self._store,
            self._clock,
            filters=[*self._filters, (filter.field_path, filter.op_string, filter.value)],
            order_field=self._order_field,
            descending=self._descending,
            after_id=self._after_id,
            limit_val=self._limit_val,
        )

    def order_by(self, field: str, direction: Any = None) -> "_FakeQuery":
        return _FakeQuery(
            self._store,
            self._clock,
            filters=self._filters,
            order_field=field,
            descending=(direction == firestore.Query.DESCENDING),
            after_id=self._after_id,
            limit_val=self._limit_val,
        )

    def start_after(self, anchor: _FakeSnapshot) -> "_FakeQuery":
        return _FakeQuery(
            self._store,
            self._clock,
            filters=self._filters,
            order_field=self._order_field,
            descending=self._descending,
            after_id=anchor.id,
            limit_val=self._limit_val,
        )

    def limit(self, value: int) -> "_FakeQuery":
        return _FakeQuery(
            self._store,
            self._clock,
            filters=self._filters,
            order_field=self._order_field,
            descending=self._descending,
            after_id=self._after_id,
            limit_val=value,
        )

    def count(self) -> _FakeCountQuery:
        return _FakeCountQuery(len(self._matching_items()))

    def stream(self) -> list[_FakeSnapshot]:
        return [_FakeSnapshot(doc_id, data) for doc_id, data in self._matching_items()]


class _FakeCollection(_FakeQuery):
    def document(self, doc_id: str) -> _FakeDocumentRef:
        return _FakeDocumentRef(self._store, doc_id, self._clock)


class _FakeTransaction:
    def __init__(self) -> None:
        self._ops: list[tuple[str, _FakeDocumentRef, dict[str, Any]]] = []
        self._max_attempts = 1
        self._read_only = False
        self._id = b"fake-tx"

    def create(self, ref: _FakeDocumentRef, data: dict[str, Any]) -> None:
        self._ops.append(("create", ref, data))

    def update(self, ref: _FakeDocumentRef, data: dict[str, Any]) -> None:
        self._ops.append(("update", ref, data))

    def _begin(self, retry_id: Any = None) -> None:
        self._ops.clear()

    def _clean_up(self) -> None:
        self._ops.clear()

    def _rollback(self) -> None:
        self._ops.clear()

    def _commit(self) -> list[Any]:
        for op, ref, data in self._ops:
            if op == "create":
                ref.create(data)
            elif op == "update":
                ref.update(data)
        self._ops.clear()
        return []


class _FakeFirestoreClient:
    def __init__(self) -> None:
        self._collections: dict[str, dict[str, dict[str, Any]]] = {}
        self._clock = _FakeClock()

    def collection(self, name: str) -> _FakeCollection:
        store = self._collections.setdefault(name, {})
        return _FakeCollection(store, self._clock)

    def transaction(self) -> _FakeTransaction:
        return _FakeTransaction()


class _ProdSettings:
    firebase_auth_required = True
    environment = "production"
    firebase_project_id = "agentshield-prod"
    firebase_auth_emulator_host = None
    google_application_credentials = None
    database_mode = "firestore"
    rate_limit_backend = "memory"
    rate_limit_requests = 1000000
    rate_limit_window_seconds = 60
    rate_limit_fail_open = False
    max_request_bytes = 262144
    trusted_proxy_count = 0
    dev_auth_identities = ""
    dev_auth_allow_remote = False


@pytest.fixture
def fake_users_env(monkeypatch):
    client = _FakeFirestoreClient()
    repo = FirestoreUserRepository(client=client)

    # In-memory fake Firebase Auth directory keyed by uid
    auth_users: dict[str, dict[str, Any]] = {
        "admin-1": {
            "uid": "admin-1",
            "email": "admin@agentshield.test",
            "email_verified": True,
            "display_name": "Admin One",
            "custom_claims": {"role": "ADMIN"},
            "disabled": False,
        },
        "user-1": {
            "uid": "user-1",
            "email": "alice@agentshield.test",
            "email_verified": False,
            "display_name": "Alice",
            "custom_claims": {},
            "disabled": False,
        },
        "user-2": {
            "uid": "user-2",
            "email": "bob@agentshield.test",
            "email_verified": True,
            "display_name": "Bob",
            "custom_claims": {"role": "REVIEWER"},
            "disabled": False,
        },
    }

    def fake_verify(token: str) -> dict[str, Any]:
        # Token string is just "<uid>" for unit tests
        if token not in auth_users:
            raise ValueError("Invalid token")
        u = auth_users[token]
        return {
            "uid": u["uid"],
            "email": u["email"],
            "email_verified": u["email_verified"],
            "name": u["display_name"],
            "role": u["custom_claims"].get("role", "VIEWER"),
            "aud": "agentshield-prod",
        }

    class _FakeAuthModule:
        class UserNotFoundError(Exception):
            pass

        @staticmethod
        def get_user(uid: str, app: Any = None):
            if uid not in auth_users:
                raise _FakeAuthModule.UserNotFoundError(uid)
            u = auth_users[uid]
            return SimpleNamespace(**u)

        @staticmethod
        def set_custom_user_claims(uid: str, claims: dict[str, Any], app: Any = None):
            if uid not in auth_users:
                raise _FakeAuthModule.UserNotFoundError(uid)
            auth_users[uid]["custom_claims"] = dict(claims)

        @staticmethod
        def update_user(uid: str, disabled: bool = False, app: Any = None):
            if uid not in auth_users:
                raise _FakeAuthModule.UserNotFoundError(uid)
            auth_users[uid]["disabled"] = disabled

    import firebase_admin

    monkeypatch.setattr(auth_module, "get_settings", lambda: _ProdSettings())
    monkeypatch.setattr(auth_module, "verify_firebase_id_token", fake_verify)
    monkeypatch.setattr(users_api, "get_firebase_app", lambda: "fake-app")
    monkeypatch.setattr(admin_api, "get_firebase_app", lambda: "fake-app")
    monkeypatch.setattr(firebase_admin, "auth", _FakeAuthModule)

    app.dependency_overrides[users_api.get_user_repository] = lambda: repo
    app.dependency_overrides[admin_api.get_optional_user_repository] = lambda: repo

    with TestClient(app) as test_client:
        yield test_client, repo, client, auth_users

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Model & repository validation tests
# ---------------------------------------------------------------------------


def test_user_profile_validates_all_fields_and_types() -> None:
    now = datetime.now(UTC)
    profile = UserProfile(
        uid="uid-123",
        email="User@Example.COM",
        display_name="  Jane Doe ",
        role="VIEWER",
        email_verified=False,
        status="ACTIVE",
        created_at=now,
        updated_at=now,
        last_login_at=None,
    )
    assert profile.uid == "uid-123"
    assert profile.email == "user@example.com"
    assert profile.display_name == "Jane Doe"
    assert profile.role == UserRole.VIEWER
    assert profile.status == UserStatus.ACTIVE
    assert profile.last_login_at is None


def test_user_profile_rejects_invalid_types_roles_statuses_and_passwords() -> None:
    now = datetime.now(UTC)
    base = {
        "uid": "uid-1",
        "email": "u@example.com",
        "display_name": "U",
        "role": "VIEWER",
        "email_verified": False,
        "status": "ACTIVE",
        "created_at": now,
        "updated_at": now,
        "last_login_at": None,
    }
    # Invalid role
    with pytest.raises(ValueError):
        UserProfile(**{**base, "role": "SUPERADMIN"})
    # Invalid status
    with pytest.raises(ValueError):
        UserProfile(**{**base, "status": "PENDING"})
    # Strict boolean for email_verified
    with pytest.raises(ValueError):
        UserProfile(**{**base, "email_verified": "true"})
    with pytest.raises(ValueError):
        UserProfile(**{**base, "email_verified": 1})
    # display_name must be string, never null
    with pytest.raises(ValueError):
        UserProfile(**{**base, "display_name": None})
    # Extra / password fields forbidden
    with pytest.raises(ValueError):
        UserProfile(**{**base, "password": "secret"})


def test_repository_never_stores_passwords_and_never_overwrites_existing_record() -> None:
    client = _FakeFirestoreClient()
    repo = FirestoreUserRepository(client=client)

    created = repo.create_user(
        uid="uid-existing",
        email="existing@example.com",
        display_name="Existing",
        role=UserRole.ADMIN,
        email_verified=True,
        status=UserStatus.ACTIVE,
    )
    assert created.role == UserRole.ADMIN
    assert created.last_login_at is None

    with pytest.raises(UserAlreadyExistsError):
        repo.create_user(uid="uid-existing", email="other@example.com")

    # Registration call must NOT overwrite existing ADMIN record!
    profile, was_created = repo.create_user_on_registration(
        uid="uid-existing",
        email="attacker@example.com",
        display_name="Overwritten",
        email_verified=False,
    )
    assert was_created is False
    assert profile.role == UserRole.ADMIN
    assert profile.email == "existing@example.com"
    assert profile.email_verified is True

    # Ensure raw Firestore doc contains exact 9 fields and zero password fields
    raw_doc = client._collections["users"]["uid-existing"]
    assert set(raw_doc.keys()) == {
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
    assert all("password" not in k for k in raw_doc)


# ---------------------------------------------------------------------------
# End-to-end API lifecycle tests
# ---------------------------------------------------------------------------


def test_user_registration_creates_viewer_profile_and_rejects_client_role(fake_users_env) -> None:
    test_client, repo, raw_client, _ = fake_users_env

    # Unauthenticated registration rejected
    assert test_client.post("/api/v1/users/register").status_code == 401

    # Frontend-supplied role escalation rejected with 422
    escalation = test_client.post(
        "/api/v1/users/register",
        headers={"Authorization": "Bearer user-1"},
        json={"role": "ADMIN"},
    )
    assert escalation.status_code == 422

    # Valid registration creates users/{uid} with default VIEWER role
    res = test_client.post("/api/v1/users/register", headers={"Authorization": "Bearer user-1"})
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["uid"] == "user-1"
    assert body["email"] == "alice@agentshield.test"
    assert body["display_name"] == "Alice"
    assert body["role"] == "VIEWER"
    assert body["email_verified"] is False
    assert body["status"] == "ACTIVE"
    assert body["created_at"] is not None
    assert body["updated_at"] is not None
    assert body["last_login_at"] is None
    assert "user-1" in raw_client._collections["users"]

    # Calling register again does not overwrite existing profile
    stored = repo.get_by_uid("user-1")
    assert stored is not None
    res_again = test_client.post("/api/v1/users/register", headers={"Authorization": "Bearer user-1"})
    assert res_again.status_code == 200
    assert res_again.json()["created_at"] == body["created_at"]


def test_email_verification_sync_and_login_timestamp(fake_users_env) -> None:
    test_client, repo, _, auth_users = fake_users_env

    # 1. Register unverified user
    reg = test_client.post("/api/v1/users/register", headers={"Authorization": "Bearer user-1"})
    assert reg.status_code == 201
    assert reg.json()["email_verified"] is False
    assert reg.json()["last_login_at"] is None
    created_at = reg.json()["created_at"]

    # 2. Protected operational endpoints still block unverified user
    assert test_client.get("/api/v1/events", headers={"Authorization": "Bearer user-1"}).status_code == 403

    # 3. Simulate email verification and email update in Firebase Authentication
    auth_users["user-1"]["email_verified"] = True
    auth_users["user-1"]["email"] = "alice.verified@agentshield.test"

    sync_res = test_client.post("/api/v1/users/sync", headers={"Authorization": "Bearer user-1"})
    assert sync_res.status_code == 200, sync_res.text
    synced = sync_res.json()
    assert synced["email_verified"] is True
    assert synced["email"] == "alice.verified@agentshield.test"
    assert synced["role"] == "VIEWER"
    assert synced["created_at"] == created_at
    assert synced["last_login_at"] is None

    # 4. Login updates last_login_at while preserving created_at and role
    login_res = test_client.post("/api/v1/users/login", headers={"Authorization": "Bearer user-1"})
    assert login_res.status_code == 200, login_res.text
    logged_in = login_res.json()
    assert logged_in["last_login_at"] is not None
    assert logged_in["created_at"] == created_at
    assert logged_in["role"] == "VIEWER"
    assert repo.get_by_uid("user-1").last_login_at is not None


def test_unauthorized_and_admin_role_modification(fake_users_env) -> None:
    test_client, repo, _, auth_users = fake_users_env

    # Register user-1 (VIEWER) and admin-1 (pre-existing Auth admin)
    assert test_client.post("/api/v1/users/register", headers={"Authorization": "Bearer user-1"}).status_code == 201

    # VIEWER cannot modify their own role or anyone else's role
    assert (
        test_client.post(
            "/api/v1/admin/users/user-1/role",
            headers={"Authorization": "Bearer user-1"},
            json={"role": "ADMIN"},
        ).status_code
        == 403
    )

    # REVIEWER cannot modify roles
    assert (
        test_client.post(
            "/api/v1/admin/users/user-1/role",
            headers={"Authorization": "Bearer user-2"},
            json={"role": "ADMIN"},
        ).status_code
        == 403
    )

    # ADMIN cannot modify their own role (neither demote nor self-modify)
    assert (
        test_client.post(
            "/api/v1/admin/users/admin-1/role",
            headers={"Authorization": "Bearer admin-1"},
            json={"role": "VIEWER"},
        ).status_code
        == 403
    )
    assert (
        test_client.post(
            "/api/v1/admin/users/admin-1/role",
            headers={"Authorization": "Bearer admin-1"},
            json={"role": "ADMIN"},
        ).status_code
        == 403
    )

    # ADMIN successfully promotes user-1 to REVIEWER
    res = test_client.post(
        "/api/v1/admin/users/user-1/role",
        headers={"Authorization": "Bearer admin-1"},
        json={"role": "REVIEWER"},
    )
    assert res.status_code == 200, res.text
    assert res.json() == {"uid": "user-1", "role": "REVIEWER", "assigned_by": "admin-1"}
    assert auth_users["user-1"]["custom_claims"]["role"] == "REVIEWER"
    updated_doc = repo.get_by_uid("user-1")
    assert updated_doc is not None
    assert updated_doc.role == UserRole.REVIEWER

    # ADMIN disables user-1 -> subsequent login is blocked with 403
    status_res = test_client.post(
        "/api/v1/admin/users/user-1/status",
        headers={"Authorization": "Bearer admin-1"},
        json={"status": "DISABLED"},
    )
    assert status_res.status_code == 200
    assert status_res.json()["status"] == "DISABLED"
    auth_users["user-1"]["disabled"] = False  # verify Firestore status check alone blocks login too
    assert test_client.post("/api/v1/users/login", headers={"Authorization": "Bearer user-1"}).status_code == 403

    # /api/v1/users/me and /api/v1/admin/users endpoints
    me_res = test_client.get("/api/v1/users/me", headers={"Authorization": "Bearer user-1"})
    assert me_res.status_code == 200
    assert me_res.json()["role"] == "REVIEWER"
    assert test_client.get("/api/v1/admin/users", headers={"Authorization": "Bearer user-1"}).status_code == 403
    list_res = test_client.get("/api/v1/admin/users", headers={"Authorization": "Bearer admin-1"})
    assert list_res.status_code == 200
    assert list_res.json()["total"] == 1
    assert list_res.json()["items"][0]["uid"] == "user-1"
