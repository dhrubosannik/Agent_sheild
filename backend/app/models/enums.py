from enum import Enum


class SecurityDecision(str, Enum):
    ALLOW = "ALLOW"
    REDACT = "REDACT"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    BLOCK = "BLOCK"


class DestinationClass(str, Enum):
    APPROVED = "APPROVED"
    UNAPPROVED = "UNAPPROVED"
    INTERNAL = "INTERNAL"
    UNKNOWN = "UNKNOWN"


class ExecutionStatus(str, Enum):
    NOT_EXECUTED = "NOT_EXECUTED"
    EXECUTED = "EXECUTED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    REDACTED_AND_EXECUTED = "REDACTED_AND_EXECUTED"
    FAILED = "FAILED"


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
