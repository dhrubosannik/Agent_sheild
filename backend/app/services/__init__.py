"""AgentShield security services package."""

from .destination_classifier import classify_destination
from .injection_detector import detect_prompt_injection
from .payload_normalizer import (
    NormalizationError,
    compute_payload_fingerprint,
    normalize_arguments,
    normalize_value,
)
from .policy_evaluator import EvaluationDecision, evaluate_policy
from .redaction_service import REDACTION_MARKER, redact_arguments
from .security_engine import evaluate_tool_call
from .sensitive_data_detector import (
    SensitiveDetectionResult,
    SensitiveFinding,
    detect_sensitive_data,
)

__all__ = [
    "classify_destination",
    "compute_payload_fingerprint",
    "detect_prompt_injection",
    "detect_sensitive_data",
    "evaluate_policy",
    "evaluate_tool_call",
    "get_audit_logger",
    "normalize_arguments",
    "normalize_value",
    "redact_arguments",
    "reset_audit_logger_singleton",
    "AuditLogger",
    "EvaluationDecision",
    "NormalizationError",
    "REDACTION_MARKER",
    "SensitiveDetectionResult",
    "SensitiveFinding",
]


_LAZY_AUDIT_EXPORTS = {"AuditLogger", "get_audit_logger", "reset_audit_logger_singleton"}


def __getattr__(name: str):
    # audit_logger imports the storage layer, which imports
    # services.audit_integrity; importing it lazily avoids a package cycle.
    if name in _LAZY_AUDIT_EXPORTS:
        from . import audit_logger

        return getattr(audit_logger, name)
    raise AttributeError(name)
