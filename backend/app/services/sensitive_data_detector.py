"""Sensitive data detection service for AgentShield."""

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..core.policy_models import PolicyConfiguration, ProtectedValue

# Pattern for valid email addresses
EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# Common API-key-like patterns (prefixed or structured token formats)
API_KEY_PATTERNS = [
    re.compile(r"\b(?:sk-[a-zA-Z0-9]{20,})\b"),
    re.compile(r"\b(?:ghp_[a-zA-Z0-9]{30,})\b"),
    re.compile(r"\b(?:gho_[a-zA-Z0-9]{30,})\b"),
    re.compile(r"\b(?:AKIA[0-9A-Z]{16})\b"),
    re.compile(r"\b(?:AIza[0-9A-Za-z-_]{35})\b"),
    re.compile(r"\b(?:key-[a-zA-Z0-9]{24,})\b"),
    re.compile(r"(?i)\b(?:api[_-]?key|secret[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?"),
]

# Common authentication tokens (JWT and Bearer headers)
AUTH_TOKEN_PATTERNS = [
    re.compile(r"\beyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b"),
]


class SensitiveFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str = Field(min_length=1)
    location: str = Field(min_length=1)
    detection_type: str = Field(min_length=1)
    severity: str = Field(min_length=1)
    is_configured_secret: bool


class SensitiveDetectionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data_labels: list[str] = Field(default_factory=list)
    findings: list[SensitiveFinding] = Field(default_factory=list)


def _scan_text(
    text: str,
    location: str,
    protected_values: list[ProtectedValue],
    findings: list[SensitiveFinding],
    detected_labels: set[str],
) -> None:
    """Scans a single text string for configured secrets and sensitive patterns."""
    # 1. Configured protected values (e.g. DEMO_SECRET)
    for pv in protected_values:
        if pv.value and pv.value in text:
            detected_labels.add("PROTECTED")
            findings.append(
                SensitiveFinding(
                    label="PROTECTED",
                    location=location,
                    detection_type="configured_secret",
                    severity="HIGH",
                    is_configured_secret=True,
                )
            )

    # 2. API key patterns
    for pattern in API_KEY_PATTERNS:
        if pattern.search(text):
            detected_labels.add("API_KEY")
            findings.append(
                SensitiveFinding(
                    label="API_KEY",
                    location=location,
                    detection_type="pattern",
                    severity="HIGH",
                    is_configured_secret=False,
                )
            )
            break

    # 3. Auth token patterns
    for pattern in AUTH_TOKEN_PATTERNS:
        if pattern.search(text):
            detected_labels.add("AUTH_TOKEN")
            findings.append(
                SensitiveFinding(
                    label="AUTH_TOKEN",
                    location=location,
                    detection_type="pattern",
                    severity="HIGH",
                    is_configured_secret=False,
                )
            )
            break

    # 4. Email pattern
    if EMAIL_REGEX.search(text):
        detected_labels.add("EMAIL")
        findings.append(
            SensitiveFinding(
                label="EMAIL",
                location=location,
                detection_type="pattern",
                severity="LOW",
                is_configured_secret=False,
            )
        )


def _traverse_payload(
    value: Any,
    location: str,
    protected_values: list[ProtectedValue],
    findings: list[SensitiveFinding],
    detected_labels: set[str],
) -> None:
    """Recursively traverses payload values and scans strings."""
    if isinstance(value, str):
        _scan_text(value, location or "payload", protected_values, findings, detected_labels)
    elif isinstance(value, dict):
        for k, v in value.items():
            child_loc = f"{location}.{k}" if location else str(k)
            # Also check if the key itself contains protected values
            if isinstance(k, str):
                _scan_text(k, f"{child_loc}[key]", protected_values, findings, detected_labels)
            _traverse_payload(v, child_loc, protected_values, findings, detected_labels)
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            child_loc = f"{location}[{idx}]"
            _traverse_payload(item, child_loc, protected_values, findings, detected_labels)


def detect_sensitive_data(
    payload: dict[str, Any],
    policy: PolicyConfiguration | None = None,
    extra_protected_values: list[ProtectedValue] | None = None,
) -> SensitiveDetectionResult:
    """Inspects a tool-call payload for configured secrets and sensitive data patterns.

    Returns structured findings without ever including the secret values themselves.
    """
    protected_values: list[ProtectedValue] = []
    if policy and policy.protected_values:
        protected_values.extend(policy.protected_values)
    if extra_protected_values:
        protected_values.extend(extra_protected_values)

    findings: list[SensitiveFinding] = []
    detected_labels: set[str] = set()

    _traverse_payload(payload, "", protected_values, findings, detected_labels)

    # Sort labels deterministically
    sorted_labels = sorted(detected_labels)

    return SensitiveDetectionResult(
        data_labels=sorted_labels,
        findings=findings,
    )
