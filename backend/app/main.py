"""AgentShield FastAPI application entrypoint."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api.approvals import router as approvals_router
from .api.demo import router as demo_router
from .api.evaluation import router as evaluation_router
from .api.events import router as events_router
from .api.health import router as health_router
from .api.policies import router as policies_router
from .api.admin import router as admin_router
from .core.config import get_settings
from .storage.database import get_database
from .core.security_middleware import SecurityHardeningMiddleware

settings = get_settings()

if settings.environment.lower() == "production":
    local_origins = {"http://127.0.0.1:5173", "http://localhost:5173"}
    production_origins = {
        origin.strip()
        for origin in settings.cors_origins.split(",")
        if origin.strip()
    }
    if production_origins & local_origins or not production_origins:
        raise RuntimeError(
            "Production CORS origins must exclude local development origins."
        )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    # Ensure database and tables are safely initialized at startup
    get_database()
    yield


app = FastAPI(
    title=settings.application_name,
    version=settings.application_version,
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in settings.cors_origins.split(",")
        if origin.strip()
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
app.add_middleware(SecurityHardeningMiddleware)

# Register routers
app.include_router(health_router)
app.include_router(evaluation_router)
app.include_router(events_router)
app.include_router(approvals_router)
app.include_router(policies_router)
app.include_router(demo_router)
app.include_router(admin_router)
