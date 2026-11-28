"""Email verification end-to-end against the Auth emulator and the real API."""


def _events(api, token):
    return api.get("/api/v1/events", headers={"Authorization": f"Bearer {token}"})


def test_unverified_then_stale_then_refreshed_token(emulator, api) -> None:
    email = "verify-flow@agentshield.test"
    account = emulator.sign_up(email)
    unverified_token = account["idToken"]

    # 1. Unverified account is rejected.
    res = _events(api, unverified_token)
    assert res.status_code == 403
    assert "Email verification is required" in res.json()["detail"]

    # 2. Verify the email (as clicking the emailed link would).
    emulator.send_verification(unverified_token)
    emulator.apply_verification(email)

    # 3. The token minted before verification still says email_verified=false:
    #    this is the stale-token bug the frontend must avoid.
    stale = _events(api, unverified_token)
    assert stale.status_code == 403

    # 4. A force-refreshed token carries email_verified=true and is accepted.
    refreshed = emulator.refresh(account["refreshToken"])
    ok = _events(api, refreshed)
    assert ok.status_code == 200, ok.text


def test_missing_and_invalid_tokens_rejected(emulator, api) -> None:
    assert api.get("/api/v1/events").status_code == 401
    assert _events(api, "not-a-token").status_code == 401


def test_role_claim_comes_from_refreshed_token(emulator, api) -> None:
    user = emulator.verified_user("viewer-to-admin@agentshield.test")
    assert api.post(
        "/api/v1/admin/users/someone/role",
        headers={"Authorization": f"Bearer {user['token']}"},
        json={"role": "VIEWER"},
    ).status_code == 403
    emulator.set_role(user["uid"], "ADMIN")
    admin_token = emulator.refresh(user["refresh"])
    other = emulator.sign_up("target@agentshield.test")
    res = api.post(
        f"/api/v1/admin/users/{other['localId']}/role",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"role": "REVIEWER"},
    )
    assert res.status_code == 200, res.text
