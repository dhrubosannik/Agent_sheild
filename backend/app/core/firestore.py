"""Optional Firestore integration using Firebase Admin SDK."""

from functools import lru_cache
from typing import Any

from google.cloud import firestore

from .config import get_settings
from .firebase import get_firebase_app


class FirestoreConfigurationError(RuntimeError):
    pass


@lru_cache
def get_firestore_client() -> Any:
    settings = get_settings()
    if settings.database_mode.lower() != "firestore":
        raise FirestoreConfigurationError("Firestore database mode is not enabled")
    app = get_firebase_app()
    if app is None:
        raise FirestoreConfigurationError("Firebase Admin is not initialized")
    return firestore.client(app=app)
