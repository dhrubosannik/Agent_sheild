"""Firebase Admin initialization and official token verification.

The Firebase target (none / emulator / cloud) is chosen and validated in
``firebase_config``; this module never guesses between emulator and cloud.
"""

from functools import lru_cache
import os
from typing import Any

import firebase_admin
from firebase_admin import auth, credentials

from .config import get_settings
from .firebase_config import (
    FirebaseConfigurationError,
    emulator_hosts,
    enforce_firebase_configuration,
    firebase_target,
)

__all__ = ["FirebaseConfigurationError", "get_firebase_app", "verify_firebase_id_token"]


@lru_cache
def get_firebase_app() -> Any | None:
    settings = get_settings()
    target = firebase_target(settings)
    if target == "none":
        return None
    enforce_firebase_configuration(settings)

    if target == "emulator":
        auth_host, firestore_host = emulator_hosts(settings)
        os.environ["FIREBASE_AUTH_EMULATOR_HOST"] = auth_host
        if firestore_host:
            os.environ["FIRESTORE_EMULATOR_HOST"] = firestore_host

    try:
        try:
            return firebase_admin.get_app()
        except ValueError:
            pass

        credential = None
        if target == "cloud":
            credential = (
                credentials.Certificate(os.path.expanduser(settings.google_application_credentials))
                if settings.google_application_credentials
                else credentials.ApplicationDefault()
            )
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
