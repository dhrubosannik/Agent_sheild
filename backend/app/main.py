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
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Register routers
app.include_router(health_router)
app.include_router(evaluation_router)
app.include_router(events_router)
app.include_router(approvals_router)
app.include_router(policies_router)
app.include_router(demo_router)
