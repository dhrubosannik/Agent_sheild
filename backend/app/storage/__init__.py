"""Storage package exporting repositories and database manager."""

from .approval_repository import (
    ApprovalAlreadyExistsError,
    ApprovalConflictError,
    ApprovalNotFoundError,
    ApprovalRepository,
    ApprovalUnauthorizedError,
)
from .audit_repository import AuditRepository
from .database import Database, get_database, reset_database_singleton
from .firestore_policy_repository import (
    FirestorePolicyRepository,
    PolicyAlreadyExistsError,
    PolicyNotFoundError,
    StoredPolicyValidationError,
)
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
    "ApprovalAlreadyExistsError",
    "ApprovalConflictError",
    "ApprovalNotFoundError",
    "ApprovalRepository",
    "ApprovalUnauthorizedError",
    "AuditRepository",
    "Database",
    "FirestorePolicyRepository",
    "FirestoreSecurityEventRepository",
    "FirestoreUserRepository",
    "PolicyAlreadyExistsError",
    "PolicyNotFoundError",
    "SecurityEventConflictError",
    "SecurityEventDuplicateError",
    "SecurityEventValidationError",
    "StoredPolicyValidationError",
    "UserAlreadyExistsError",
    "UserDisabledError",
    "UserNotFoundError",
    "UserPermissionError",
    "UserValidationError",
    "get_database",
    "reset_database_singleton",
]
