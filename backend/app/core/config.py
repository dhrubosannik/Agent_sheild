from functools import lru_cache
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
    firebase_project_id: str | None = None
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

    model_config = SettingsConfigDict(
        env_file=".env",
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
