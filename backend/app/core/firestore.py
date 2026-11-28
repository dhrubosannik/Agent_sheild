"""Optional Firestore integration using Firebase Admin SDK and emulator support."""

import os
from functools import lru_cache
import os
from typing import Any

import google.auth.credentials
from google.cloud import firestore as gc_firestore

from .config import get_settings
from .firebase import get_firebase_app


class FirestoreConfigurationError(RuntimeError):
    pass


@lru_cache
def get_firestore_client() -> Any:
    settings = get_settings()
    if settings.database_mode.lower() != "firestore":
        raise FirestoreConfigurationError("Firestore database mode is not enabled")
    if settings.firestore_emulator_host and "FIRESTORE_EMULATOR_HOST" not in os.environ:
        os.environ["FIRESTORE_EMULATOR_HOST"] = settings.firestore_emulator_host
    app = get_firebase_app()
    if app is None:
        raise FirestoreConfigurationError("Firebase Admin is not initialized")

    emulator_host = os.environ.get("FIRESTORE_EMULATOR_HOST") or settings.firestore_emulator_host
    if emulator_host:
        return gc_firestore.Client(
            project=settings.firebase_project_id,
            credentials=google.auth.credentials.AnonymousCredentials(),
        )

    try:
        from firebase_admin import firestore as fa_firestore
        return fa_firestore.client(app=app)
    except Exception:
        return gc_firestore.Client(project=settings.firebase_project_id)
