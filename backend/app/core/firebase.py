"""Firebase Admin initialization and official token verification."""

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

    try:
        try:
            return firebase_admin.get_app()
        except ValueError:
            pass

        credential = None
        if settings.google_application_credentials:
            credential = credentials.Certificate(settings.google_application_credentials)
        elif settings.environment != "development":
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
