"""Firestore users collection end-to-end tests against Auth + Firestore emulators."""

from __future__ import annotations

from datetime import datetime


def test_user_registration_sync_login_and_role_lifecycle(emulator, api, firestore_client) -> None:
    # 1. Register a brand-new user in Firebase Auth (unverified)
    email = "new-viewer@agentshield.test"
    account = emulator.sign_up(email)
    uid = account["localId"]
    unverified_token = account["idToken"]

    # Frontend-supplied role escalation attempt must be rejected
    bad_reg = api.post(
        "/api/v1/users/register",
        headers={"Authorization": f"Bearer {unverified_token}"},
        json={"role": "ADMIN"},
    )
    assert bad_reg.status_code == 422

    # Register user profile in Firestore `users/{uid}`
    reg = api.post(
        "/api/v1/users/register",
        headers={"Authorization": f"Bearer {unverified_token}"},
        json={"display_name": "New Viewer"},
    )
    assert reg.status_code == 201, reg.text
    profile = reg.json()
    assert profile["uid"] == uid
    assert profile["email"] == email
    assert profile["display_name"] == "New Viewer"
    assert profile["role"] == "VIEWER"
    assert profile["email_verified"] is False
    assert profile["status"] == "ACTIVE"
    assert profile["last_login_at"] is None

    # Verify raw Firestore document uses Firebase Auth UID and server Timestamps
    snap = firestore_client.collection("users").document(uid).get()
    assert snap.exists
    raw = snap.to_dict()
    assert set(raw.keys()) == {
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
    assert isinstance(raw["created_at"], datetime)
    assert isinstance(raw["updated_at"], datetime)
    assert raw["last_login_at"] is None

    # 2. Verify email in Firebase Auth and synchronize Firestore `users/{uid}`
    emulator.send_verification(unverified_token)
    emulator.apply_verification(email)
    refreshed_token = emulator.refresh(account["refreshToken"])

    sync_res = api.post(
        "/api/v1/users/sync",
        headers={"Authorization": f"Bearer {refreshed_token}"},
    )
    assert sync_res.status_code == 200, sync_res.text
    assert sync_res.json()["email_verified"] is True
    assert sync_res.json()["role"] == "VIEWER"

    # 3. Login updates last_login_at without overwriting created_at or role
    session = emulator.sign_in(email)
    login_res = api.post(
        "/api/v1/users/login",
        headers={"Authorization": f"Bearer {session['idToken']}"},
    )
    assert login_res.status_code == 200, login_res.text
    assert login_res.json()["last_login_at"] is not None
    assert login_res.json()["created_at"] == profile["created_at"]

    # 4. Unauthorized role modification attempts
    assert (
        api.post(
            f"/api/v1/admin/users/{uid}/role",
            headers={"Authorization": f"Bearer {session['idToken']}"},
            json={"role": "ADMIN"},
        ).status_code
        == 403
    )

    # 5. Admin modifies another user's role; cannot modify own role
    admin = emulator.verified_user("users-admin@agentshield.test", "ADMIN")
    assert (
        api.post(
            f"/api/v1/admin/users/{admin['uid']}/role",
            headers={"Authorization": f"Bearer {admin['token']}"},
            json={"role": "VIEWER"},
        ).status_code
        == 403
    )

    promote = api.post(
        f"/api/v1/admin/users/{uid}/role",
        headers={"Authorization": f"Bearer {admin['token']}"},
        json={"role": "REVIEWER"},
    )
    assert promote.status_code == 200, promote.text
    assert promote.json()["role"] == "REVIEWER"

    # Verify Firestore document reflects REVIEWER and preserved created_at/last_login_at
    after_promote = firestore_client.collection("users").document(uid).get().to_dict()
    assert after_promote["role"] == "REVIEWER"
    assert after_promote["created_at"] == raw["created_at"]
    assert after_promote["last_login_at"] is not None

    # Re-registering does not overwrite the REVIEWER role
    rereg = api.post(
        "/api/v1/users/register",
        headers={"Authorization": f"Bearer {emulator.refresh(session['refreshToken'])}"},
    )
    assert rereg.status_code == 200
    assert rereg.json()["role"] == "REVIEWER"
