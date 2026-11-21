"""API routers package."""

from .approvals import router as approvals_router
from .evaluation import router as evaluation_router
from .events import router as events_router
from .health import router as health_router

__all__ = [
    "approvals_router",
    "evaluation_router",
    "events_router",
    "health_router",
]
