from functools import lru_cache
import os
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    application_name: str = "AgentShield"
    application_version: str = "0.1.0"
    environment: str = "development"
    backend_host: str = "127.0.0.1"
    backend_port: int = 8000
    agentshield_policy_path: str = "backend/policies/default_policy.yaml"
    agentshield_database_path: str = "data/agentshield.db"
    # none | emulator | cloud. See backend/app/core/firebase_config.py.
    firebase_target: str = "none"
    firebase_project_id: str | None = None
    # Must repeat FIREBASE_PROJECT_ID to connect a non-production machine to
    # the shared cloud project.
    firebase_cloud_project_confirm: str | None = None
    google_application_credentials: str | None = None
    firebase_auth_required: bool = False
    firebase_auth_emulator_host: str | None = None
    firestore_emulator_host: str | None = None
    database_mode: str = "sqlite"
    cors_origins: str = "http://127.0.0.1:5173,http://localhost:5173"
    audit_signing_private_key_pem: str | None = None
    audit_signing_public_key_pem: str | None = None
    max_request_bytes: int = 262144
    rate_limit_requests: int = 120
    rate_limit_window_seconds: int = 60
    # "auto" -> firestore when database_mode=firestore, else memory.
    rate_limit_backend: str = "auto"
    # Required acknowledgement to run the in-memory limiter in production:
    # it is only correct for a single application instance.
    rate_limit_single_instance: bool = False
    rate_limit_fail_open: bool = False
    # Number of trusted reverse proxies in front of the app (Render: 1). When
    # 0, X-Forwarded-For is ignored.
    trusted_proxy_count: int = 0
    # Explicit development identities, "uid:ROLE,uid2:ROLE". Used only when
    # firebase_auth_required is false and environment is not production, and
    # only when the request names one via the X-AgentShield-Dev-User header.
    dev_auth_identities: str = ""
    dev_auth_allow_remote: bool = False

    # AGENTSHIELD_ENV_FILE selects the env file (e.g. .env.emulator or
    # .env.cloud) so emulator and cloud configurations stay separate.
    model_config = SettingsConfigDict(
        env_file=os.environ.get("AGENTSHIELD_ENV_FILE", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


def resolve_policy_path(path: str | None = None) -> Path:
    configured = path or get_settings().agentshield_policy_path
    candidate = Path(configured).expanduser()
    if not candidate.is_absolute():
        project_root = Path(__file__).resolve().parents[3]
        candidate = project_root / candidate
    return candidate.resolve()


def resolve_database_path(path: str | None = None) -> Path:
    configured = path or get_settings().agentshield_database_path
    candidate = Path(configured).expanduser()
    if not candidate.is_absolute():
        project_root = Path(__file__).resolve().parents[3]
        candidate = project_root / candidate
    candidate.parent.mkdir(parents=True, exist_ok=True)
    return candidate.resolve()
