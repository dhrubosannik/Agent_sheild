"""AgentShield FastAPI application entrypoint."""

from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator
from fastapi import FastAPI

from .api.approvals import router as approvals_router
from .api.evaluation import router as evaluation_router
from .api.events import router as events_router
from .api.health import router as health_router
from .core.config import get_settings
from .storage.database import get_database

settings = get_settings()


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

# Register routers
app.include_router(health_router)
app.include_router(evaluation_router)
app.include_router(events_router)
app.include_router(approvals_router)
