from fastapi import FastAPI

from .core.config import get_settings


settings = get_settings()

app = FastAPI(
    title=settings.application_name,
    version=settings.application_version,
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {
        "name": settings.application_name,
        "status": "healthy",
        "version": settings.application_version,
    }
