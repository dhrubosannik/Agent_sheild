"""Storage package exporting repositories and database manager."""

from .approval_repository import (
    ApprovalConflictError,
    ApprovalNotFoundError,
    ApprovalRepository,
)
from .audit_repository import AuditRepository
from .database import Database, get_database, reset_database_singleton
from .firestore_security_event_repository import (
    FirestoreSecurityEventRepository,
    SecurityEventConflictError,
    SecurityEventDuplicateError,
    SecurityEventValidationError,
)
from .firestore_user_repository import (
    FirestoreUserRepository,
    UserAlreadyExistsError,
    UserDisabledError,
    UserNotFoundError,
    UserPermissionError,
    UserValidationError,
)

__all__ = [
    "ApprovalConflictError",
    "ApprovalNotFoundError",
    "ApprovalRepository",
    "AuditRepository",
    "Database",
    "FirestoreSecurityEventRepository",
    "FirestoreUserRepository",
    "SecurityEventConflictError",
    "SecurityEventDuplicateError",
    "SecurityEventValidationError",
    "UserAlreadyExistsError",
    "UserDisabledError",
    "UserNotFoundError",
    "UserPermissionError",
    "UserValidationError",
    "get_database",
    "reset_database_singleton",
]
