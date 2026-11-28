"""Firebase Admin initialization and official token verification."""

import os
from functools import lru_cache
from typing import Any

import firebase_admin
from firebase_admin import auth, credentials

from .config import get_settings


class FirebaseConfigurationError(RuntimeError):
    pass


@lru_cache
def get_firebase_app() -> Any | None:
    settings = get_settings()
    if not settings.firebase_project_id:
        return None

    if settings.firebase_auth_emulator_host and "FIREBASE_AUTH_EMULATOR_HOST" not in os.environ:
        os.environ["FIREBASE_AUTH_EMULATOR_HOST"] = settings.firebase_auth_emulator_host

    try:
        try:
            return firebase_admin.get_app()
        except ValueError:
            pass

        import os
        emulator_host = os.environ.get("FIREBASE_AUTH_EMULATOR_HOST") or settings.firebase_auth_emulator_host
        if emulator_host:
            os.environ["FIREBASE_AUTH_EMULATOR_HOST"] = emulator_host

        credential = None
        if settings.google_application_credentials:
            credential = credentials.Certificate(settings.google_application_credentials)
        elif settings.environment != "development" and not emulator_host:
            credential = credentials.ApplicationDefault()

        return firebase_admin.initialize_app(
            credential,
            {"projectId": settings.firebase_project_id},
        )
    except Exception as exc:
        raise FirebaseConfigurationError("Firebase Admin initialization failed") from exc


def verify_firebase_id_token(id_token: str) -> dict[str, Any]:
    settings = get_settings()
    if not settings.firebase_project_id:
        raise FirebaseConfigurationError("Firebase project identity is not configured")

    app = get_firebase_app()
    if app is None:
        raise FirebaseConfigurationError("Firebase Admin is not initialized")

    decoded = auth.verify_id_token(id_token, app=app)
    token_project = decoded.get("aud")
    if token_project != settings.firebase_project_id:
        raise FirebaseConfigurationError("Firebase ID token project identity mismatch")
    return decoded
