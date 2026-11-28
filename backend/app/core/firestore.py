"""Optional Firestore integration using Firebase Admin SDK and emulator support."""

from functools import lru_cache
import os
from typing import Any

import google.auth.credentials
from google.cloud import firestore as gc_firestore

from .config import get_settings
from .firebase import get_firebase_app
from .firebase_config import emulator_hosts, firebase_target


class FirestoreConfigurationError(RuntimeError):
    pass


@lru_cache
def get_firestore_client() -> Any:
    settings = get_settings()
    if settings.database_mode.lower() != "firestore" and settings.rate_limit_backend.lower() != "firestore":
        raise FirestoreConfigurationError("Firestore is not enabled (DATABASE_MODE / RATE_LIMIT_BACKEND)")
    target = firebase_target(settings)
    if target == "none":
        raise FirestoreConfigurationError("Firestore requires FIREBASE_TARGET=emulator or FIREBASE_TARGET=cloud")
    app = get_firebase_app()  # validates the configuration
    if app is None:
        raise FirestoreConfigurationError("Firebase Admin is not initialized")

    if target == "emulator":
        _, firestore_host = emulator_hosts(settings)
        os.environ["FIRESTORE_EMULATOR_HOST"] = firestore_host
        return gc_firestore.Client(
            project=settings.firebase_project_id,
            credentials=google.auth.credentials.AnonymousCredentials(),
        )

    from firebase_admin import firestore as fa_firestore

    return fa_firestore.client(app=app)
