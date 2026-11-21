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
