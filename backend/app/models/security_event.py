"""Pydantic models, risk-level derivation, and metadata validation for Firestore ``security_events``."""

from __future__ import annotations

from datetime import UTC, datetime
import json
import re
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, StrictStr, field_validator

from .enums import RiskLevel, SecurityDecision
from .evaluation import EvaluationResult
from .tool_call import ToolCall

SECURITY_EVENT_FIELDS = frozenset(
    {
        "event_id",
        "user_id",
        "agent_id",
        "tool_name",
        "decision",
        "risk_level",
        "reason",
        "policy_id",
        "correlation_id",
        "created_at",
        "metadata",
    }
)

MAX_METADATA_BYTES = 16 * 1024
MAX_METADATA_KEYS = 50
MAX_METADATA_DEPTH = 5

_ID_RE = re.compile(r"^[^\s/]+$")
_FORBIDDEN_METADATA_KEYS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "password_hash",
        "hashed_password",
        "raw_password",
        "access_token",
        "refresh_token",
        "id_token",
        "auth_token",
        "bearer_token",
        "token",
        "api_key",
        "apikey",
        "secret",
        "secret_key",
        "client_secret",
        "private_key",
        "signing_key",
        "credentials",
        "authorization",
        "cookie",
        "session_secret",
        "raw_arguments",
        "arguments",
    }
)
_SECRET_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
    re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z\-_]{20,}\b"),
)


def validate_identifier(value: Any, *, field_name: str, max_length: int = 128) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string.")
    cleaned = value.strip()
    if not cleaned or len(cleaned) > max_length or ".." in cleaned or not _ID_RE.match(cleaned):
        raise ValueError(
            f"{field_name} must be a non-empty string up to {max_length} characters without spaces or '/'."
        )
    return cleaned


def validate_non_empty_text(value: Any, *, field_name: str, max_length: int = 500) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string.")
    cleaned = value.strip()
    if not cleaned or len(cleaned) > max_length:
        raise ValueError(f"{field_name} must be a non-empty string up to {max_length} characters.")
    return cleaned


def validate_decision(value: Any) -> SecurityDecision:
    if isinstance(value, SecurityDecision):
        return value
    if not isinstance(value, str):
        raise ValueError("decision must be a string.")
    try:
        return SecurityDecision(value)
    except ValueError as exc:
        allowed = ", ".join(d.value for d in SecurityDecision)
        raise ValueError(f"decision must be one of: {allowed}.") from exc


def validate_risk_level(value: Any) -> RiskLevel:
    if isinstance(value, RiskLevel):
        return value
    if not isinstance(value, str):
        raise ValueError("risk_level must be a string.")
    try:
        return RiskLevel(value)
    except ValueError as exc:
        allowed = ", ".join(r.value for r in RiskLevel)
        raise ValueError(f"risk_level must be one of: {allowed}.") from exc


def _check_metadata_node(node: Any, *, depth: int, key_counter: list[int]) -> None:
    if depth > MAX_METADATA_DEPTH:
        raise ValueError(f"metadata exceeds maximum nesting depth of {MAX_METADATA_DEPTH}.")
    if node is None or isinstance(node, (bool, int)):
        return
    if isinstance(node, float):
        if node != node or node in (float("inf"), float("-inf")):
            raise ValueError("metadata cannot contain NaN or infinite float values.")
        return
    if isinstance(node, str):
        for pattern in _SECRET_VALUE_PATTERNS:
            if pattern.search(node):
                raise ValueError("metadata cannot contain raw secrets, tokens, or private keys.")
        return
    if isinstance(node, list):
        for item in node:
            _check_metadata_node(item, depth=depth + 1, key_counter=key_counter)
        return
    if isinstance(node, dict):
        for raw_key, item in node.items():
            if not isinstance(raw_key, str) or not raw_key.strip():
                raise ValueError("metadata keys must be non-empty strings.")
            key_counter[0] += 1
            if key_counter[0] > MAX_METADATA_KEYS:
                raise ValueError(f"metadata exceeds maximum of {MAX_METADATA_KEYS} entries.")
            normalized_key = raw_key.strip().lower().replace("-", "_")
            if normalized_key in _FORBIDDEN_METADATA_KEYS or any(
                part in normalized_key for part in ("password", "private_key", "access_token", "refresh_token", "id_token", "api_key", "secret")
            ):
                raise ValueError(f"metadata key '{raw_key}' is not permitted because it may contain sensitive credentials.")
            _check_metadata_node(item, depth=depth + 1, key_counter=key_counter)
        return
    raise ValueError("metadata must contain only JSON/Firestore-compatible values.")


def validate_security_metadata(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("metadata must be a map/object.")
    key_counter = [0]
    _check_metadata_node(value, depth=1, key_counter=key_counter)
    try:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise ValueError("metadata must be JSON-serializable.") from exc
    if len(encoded.encode("utf-8")) > MAX_METADATA_BYTES:
        raise ValueError(f"metadata exceeds maximum allowed size of {MAX_METADATA_BYTES} bytes.")
    return dict(value)


def validate_created_at(value: Any) -> datetime:
    if value is None or isinstance(value, bool) or not isinstance(value, datetime):
        raise ValueError("created_at must be a timestamp.")
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def derive_risk_level(result: EvaluationResult) -> RiskLevel:
    """Maps an EvaluationResult to LOW / MEDIUM / HIGH / CRITICAL deterministically."""
    labels_upper = {str(label).upper() for label in result.data_labels}
    reasons_upper = {str(code).upper() for code in result.reason_codes}
    has_protected_or_injection = bool(
        {"PROTECTED", "SECRET_DETECTED", "INJECTION_DETECTED", "PROMPT_INJECTION", "API_KEY", "PRIVATE_KEY", "PASSWORD"}
        & (labels_upper | reasons_upper)
    ) or any("SECRET" in s or "PRIVATE_KEY" in s or "INJECTION" in s for s in (labels_upper | reasons_upper))

    if result.decision == SecurityDecision.BLOCK:
        return RiskLevel.CRITICAL if (has_protected_or_injection or bool(result.risk_signals)) else RiskLevel.HIGH
    if result.decision == SecurityDecision.REQUIRE_APPROVAL:
        return RiskLevel.HIGH if (has_protected_or_injection or result.risk_signals) else RiskLevel.MEDIUM
    if result.decision == SecurityDecision.REDACT:
        return RiskLevel.HIGH if result.risk_signals else RiskLevel.MEDIUM
    return RiskLevel.MEDIUM if result.risk_signals else RiskLevel.LOW


class SecurityEvent(BaseModel):
    """Canonical representation of a document in the Firestore ``security_events`` collection."""

    model_config = ConfigDict(extra="forbid")

    event_id: StrictStr
    user_id: StrictStr
    agent_id: StrictStr
    tool_name: StrictStr
    decision: SecurityDecision
    risk_level: RiskLevel
    reason: StrictStr
    policy_id: StrictStr
    correlation_id: StrictStr
    created_at: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("event_id", mode="before")
    @classmethod
    def _check_event_id(cls, value: Any) -> str:
        return validate_identifier(value, field_name="event_id", max_length=128)

    @field_validator("user_id", mode="before")
    @classmethod
    def _check_user_id(cls, value: Any) -> str:
        return validate_identifier(value, field_name="user_id", max_length=128)

    @field_validator("agent_id", mode="before")
    @classmethod
    def _check_agent_id(cls, value: Any) -> str:
        return validate_non_empty_text(value, field_name="agent_id", max_length=128)

    @field_validator("tool_name", mode="before")
    @classmethod
    def _check_tool_name(cls, value: Any) -> str:
        return validate_non_empty_text(value, field_name="tool_name", max_length=200)

    @field_validator("decision", mode="before")
    @classmethod
    def _check_decision(cls, value: Any) -> SecurityDecision:
        return validate_decision(value)

    @field_validator("risk_level", mode="before")
    @classmethod
    def _check_risk_level(cls, value: Any) -> RiskLevel:
        return validate_risk_level(value)

    @field_validator("reason", mode="before")
    @classmethod
    def _check_reason(cls, value: Any) -> str:
        return validate_non_empty_text(value, field_name="reason", max_length=1000)

    @field_validator("policy_id", mode="before")
    @classmethod
    def _check_policy_id(cls, value: Any) -> str:
        return validate_non_empty_text(value, field_name="policy_id", max_length=200)

    @field_validator("correlation_id", mode="before")
    @classmethod
    def _check_correlation_id(cls, value: Any) -> str:
        return validate_identifier(value, field_name="correlation_id", max_length=128)

    @field_validator("created_at", mode="before")
    @classmethod
    def _check_created_at(cls, value: Any) -> datetime:
        return validate_created_at(value)

    @field_validator("metadata", mode="before")
    @classmethod
    def _check_metadata(cls, value: Any) -> dict[str, Any]:
        return validate_security_metadata(value)


class SecurityEventCreateRequest(BaseModel):
    """Validated payload for backend security event ingestion."""

    model_config = ConfigDict(extra="forbid")

    event_id: StrictStr | None = None
    agent_id: StrictStr = "default-agent"
    tool_name: StrictStr
    decision: SecurityDecision
    risk_level: RiskLevel
    reason: StrictStr
    policy_id: StrictStr
    correlation_id: StrictStr | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("event_id", mode="before")
    @classmethod
    def _check_opt_event_id(cls, value: Any) -> str | None:
        if value is None:
            return None
        return validate_identifier(value, field_name="event_id", max_length=128)

    @field_validator("agent_id", mode="before")
    @classmethod
    def _check_agent_id(cls, value: Any) -> str:
        return validate_non_empty_text(value, field_name="agent_id", max_length=128)

    @field_validator("tool_name", mode="before")
    @classmethod
    def _check_tool_name(cls, value: Any) -> str:
        return validate_non_empty_text(value, field_name="tool_name", max_length=200)

    @field_validator("decision", mode="before")
    @classmethod
    def _check_decision(cls, value: Any) -> SecurityDecision:
        return validate_decision(value)

    @field_validator("risk_level", mode="before")
    @classmethod
    def _check_risk_level(cls, value: Any) -> RiskLevel:
        return validate_risk_level(value)

    @field_validator("reason", mode="before")
    @classmethod
    def _check_reason(cls, value: Any) -> str:
        return validate_non_empty_text(value, field_name="reason", max_length=1000)

    @field_validator("policy_id", mode="before")
    @classmethod
    def _check_policy_id(cls, value: Any) -> str:
        return validate_non_empty_text(value, field_name="policy_id", max_length=200)

    @field_validator("correlation_id", mode="before")
    @classmethod
    def _check_opt_correlation_id(cls, value: Any) -> str | None:
        if value is None:
            return None
        return validate_identifier(value, field_name="correlation_id", max_length=128)

    @field_validator("metadata", mode="before")
    @classmethod
    def _check_metadata(cls, value: Any) -> dict[str, Any]:
        return validate_security_metadata(value)


class SecurityEventListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[SecurityEvent]
    total: int
    limit: int
    next_cursor: str | None = None


def build_security_event_input(
    *,
    tool_call: ToolCall,
    result: EvaluationResult,
    user_id: str,
    correlation_id: str | None = None,
) -> dict[str, Any]:
    """Constructs a privacy-safe ``security_events`` input payload from an evaluation."""
    context = tool_call.context or {}
    raw_agent_id = context.get("agent_id")
    agent_id = (
        raw_agent_id.strip()
        if isinstance(raw_agent_id, str) and raw_agent_id.strip()
        else "default-agent"
    )
    resolved_correlation = (
        correlation_id.strip()
        if isinstance(correlation_id, str) and correlation_id.strip()
        else str(tool_call.request_id)
    )
    risk_signal_names = [
        signal if isinstance(signal, str) else signal.name
        for signal in result.risk_signals
    ]
    metadata: dict[str, Any] = {
        "destination_class": result.destination_class.value,
        "execution_status": result.execution_status.value,
        "reason_codes": list(result.reason_codes),
        "data_labels": list(result.data_labels),
        "risk_signals": risk_signal_names,
        "redacted": result.redacted_arguments is not None,
        "request_id": str(tool_call.request_id),
    }
    if result.payload_fingerprint:
        metadata["payload_fingerprint"] = result.payload_fingerprint

    return {
        "event_id": result.event_id,
        "user_id": user_id,
        "agent_id": agent_id[:128],
        "tool_name": tool_call.tool_name,
        "decision": result.decision,
        "risk_level": derive_risk_level(result),
        "reason": result.explanation,
        "policy_id": result.policy_id,
        "correlation_id": resolved_correlation or f"corr-{uuid4().hex[:12]}",
        "metadata": validate_security_metadata(metadata),
    }
