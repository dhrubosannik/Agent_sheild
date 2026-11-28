"""Connection-time destination enforcement for tools that make HTTP requests.

Use ``create_guarded_client()`` instead of a plain ``httpx.Client`` inside
protected tools so that DNS answers are validated (and pinned) at the moment
of connection. See ``backend.app.services.safe_network`` for details.
"""

from backend.app.services.safe_network import (
    DestinationNotPermittedError,
    GuardedTransport,
    create_guarded_client,
    resolve_and_validate,
)

__all__ = [
    "DestinationNotPermittedError",
    "GuardedTransport",
    "create_guarded_client",
    "resolve_and_validate",
]
