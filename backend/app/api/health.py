"""Health check endpoint."""

from fastapi import APIRouter

from ..core.config import get_settings

router = APIRouter(tags=["Health"])
settings = get_settings()


@router.get("/health")
def health() -> dict[str, str]:
    """Returns application name, status, and version."""
    return {
        "name": settings.application_name,
        "status": "healthy",
        "version": settings.application_version,
    }
