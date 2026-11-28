"""Firebase Emulator Suite integration tests.

Run with real Auth + Firestore emulators (rules from firestore.rules):

    JAVA_HOME=/opt/homebrew/opt/openjdk@21 firebase emulators:exec \
        --only auth,firestore --project demo-agentshield \
        "AGENTSHIELD_EMULATOR_TESTS=1 .venv/bin/python -m pytest backend/tests/emulator -q"

Skipped in the ordinary test run.
"""

import os

import pytest

RUN = os.environ.get("AGENTSHIELD_EMULATOR_TESTS") == "1"
if not RUN:
    collect_ignore_glob = ["test_*.py"]
else:
    PROJECT_ID = os.environ.get("GCLOUD_PROJECT", "demo-agentshield")
    if not PROJECT_ID.startswith("demo-"):
        raise RuntimeError("Emulator tests must use a demo-* project ID, never the shared cloud project.")
    os.environ.setdefault("FIREBASE_AUTH_EMULATOR_HOST", "127.0.0.1:9099")
    os.environ.setdefault("FIRESTORE_EMULATOR_HOST", "127.0.0.1:8080")
    os.environ.update(
        {
            "FIREBASE_TARGET": "emulator",
            "FIREBASE_PROJECT_ID": PROJECT_ID,
            "GCLOUD_PROJECT": PROJECT_ID,
            "ENVIRONMENT": "development",
            "DATABASE_MODE": "firestore",
            "FIREBASE_AUTH_REQUIRED": "true",
            "DEV_AUTH_IDENTITIES": "",
            "RATE_LIMIT_REQUESTS": "1000000",
        }
    )

    from backend.app.core.config import get_settings

    get_settings.cache_clear()

    import httpx

    AUTH = f"http://{os.environ['FIREBASE_AUTH_EMULATOR_HOST']}"
    FS = f"http://{os.environ['FIRESTORE_EMULATOR_HOST']}"
    KEY = "fake-api-key"
    IDT = f"{AUTH}/identitytoolkit.googleapis.com/v1"

    class Emulator:
        project = PROJECT_ID
        firestore_url = f"{FS}/v1/projects/{PROJECT_ID}/databases/(default)/documents"

        def __init__(self) -> None:
            self.http = httpx.Client(timeout=30)

        def reset(self) -> None:
            self.http.delete(f"{FS}/emulator/v1/projects/{PROJECT_ID}/databases/(default)/documents").raise_for_status()
            self.http.delete(f"{AUTH}/emulator/v1/projects/{PROJECT_ID}/accounts").raise_for_status()

        def sign_up(self, email: str, password: str = "Secure-Password-123") -> dict:
            res = self.http.post(f"{IDT}/accounts:signUp?key={KEY}", json={"email": email, "password": password, "returnSecureToken": True})
            res.raise_for_status()
            return res.json()

        def sign_in(self, email: str, password: str = "Secure-Password-123") -> dict:
            res = self.http.post(
                f"{IDT}/accounts:signInWithPassword?key={KEY}",
                json={"email": email, "password": password, "returnSecureToken": True},
            )
            res.raise_for_status()
            return res.json()

        def send_verification(self, id_token: str) -> None:
            self.http.post(f"{IDT}/accounts:sendOobCode?key={KEY}", json={"requestType": "VERIFY_EMAIL", "idToken": id_token}).raise_for_status()

        def apply_verification(self, email: str) -> None:
            codes = self.http.get(f"{AUTH}/emulator/v1/projects/{PROJECT_ID}/oobCodes").json()["oobCodes"]
            code = [c for c in codes if c["email"].lower() == email.lower() and c["requestType"] == "VERIFY_EMAIL"][-1]["oobCode"]
            self.http.post(f"{IDT}/accounts:update?key={KEY}", json={"oobCode": code}).raise_for_status()

        def refresh(self, refresh_token: str) -> str:
            res = self.http.post(
                f"{AUTH}/securetoken.googleapis.com/v1/token?key={KEY}",
                data={"grant_type": "refresh_token", "refresh_token": refresh_token},
            )
            res.raise_for_status()
            return res.json()["id_token"]

        def set_role(self, uid: str, role: str) -> None:
            from firebase_admin import auth

            from backend.app.core.firebase import get_firebase_app

            auth.set_custom_user_claims(uid, {"role": role}, app=get_firebase_app())

        def verified_user(self, email: str, role: str | None = None) -> dict:
            account = self.sign_up(email)
            self.send_verification(account["idToken"])
            self.apply_verification(email)
            if role:
                self.set_role(account["localId"], role)
            session = self.sign_in(email)
            return {"uid": account["localId"], "token": session["idToken"], "refresh": session["refreshToken"]}

    @pytest.fixture(scope="session")
    def emulator() -> Emulator:
        emu = Emulator()
        try:
            emu.http.get(f"{FS}/").raise_for_status()
        except Exception as exc:  # pragma: no cover
            pytest.fail(f"Firestore emulator not reachable at {FS}: {exc}")
        return emu

    @pytest.fixture(autouse=True)
    def clean(emulator):
        emulator.reset()
        yield

    @pytest.fixture
    def api(emulator):
        from fastapi.testclient import TestClient

        from backend.app.main import app

        with TestClient(app) as client:
            yield client

    @pytest.fixture
    def firestore_client():
        from backend.app.core.firestore import get_firestore_client

        return get_firestore_client()
