"""Redaction service for sanitizing sensitive tool-call arguments."""

import copy
import re
from typing import Any

from ..core.policy_models import PolicyConfiguration, ProtectedValue

REDACTION_MARKER = "[REDACTED]"

API_KEY_PATTERN = re.compile(
    r"\b(?:sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}|gho_[A-Za-z0-9]{30,}|"
    r"AKIA[0-9A-Z]{16}|AIza[A-Za-z0-9-_]{35}|key-[A-Za-z0-9]{24,})\b"
)
BEARER_PATTERN = re.compile(
    r"(?<!\S)(?:Bearer[ \t]+[A-Za-z0-9._~+/=-]+|"
    r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+)",
    re.IGNORECASE,
)


def _redact_string(text: str, protected_values: list[ProtectedValue]) -> str:
    redacted = text
    for pv in protected_values:
        if pv.value and pv.value in redacted:
            redacted = redacted.replace(pv.value, REDACTION_MARKER)
    redacted = API_KEY_PATTERN.sub(REDACTION_MARKER, redacted)
    redacted = BEARER_PATTERN.sub(REDACTION_MARKER, redacted)
    return redacted


def _redact_value(value: Any, protected_values: list[ProtectedValue]) -> Any:
    if isinstance(value, str):
        return _redact_string(value, protected_values)
    if isinstance(value, dict):
        sanitized_dict: dict[str, Any] = {}
        for k, v in value.items():
            sanitized_key = _redact_string(str(k), protected_values)
            sanitized_dict[sanitized_key] = _redact_value(v, protected_values)
        return sanitized_dict
    if isinstance(value, list):
        return [_redact_value(item, protected_values) for item in value]
    return value


def redact_arguments(
    arguments: dict[str, Any],
    policy: PolicyConfiguration | None = None,
    extra_protected_values: list[ProtectedValue] | None = None,
) -> tuple[bool, dict[str, Any] | None]:
    """Creates a sanitized deep copy of tool arguments with protected values replaced by [REDACTED].

    Returns (success, sanitized_arguments).
    If redaction fails or cannot be safely guaranteed, returns (False, None).
    The original arguments object is never mutated.
    """
    if not isinstance(arguments, dict):
        return False, None

    protected_values: list[ProtectedValue] = []
    if policy and policy.protected_values:
        protected_values.extend(policy.protected_values)
    if extra_protected_values:
        protected_values.extend(extra_protected_values)

    try:
        # Deep copy to ensure original object is preserved untouched
        safe_copy = copy.deepcopy(arguments)
        sanitized = _redact_value(safe_copy, protected_values)

        # Verify that no protected secret remains in the sanitized output
        def _contains_secret(val: Any) -> bool:
            if isinstance(val, str):
                if any(pv.value and pv.value in val for pv in protected_values):
                    return True
                return bool(API_KEY_PATTERN.search(val) or BEARER_PATTERN.search(val))
            if isinstance(val, dict):
                return any(
                    _contains_secret(k) or _contains_secret(v)
                    for k, v in val.items()
                )
            if isinstance(val, list):
                return any(_contains_secret(item) for item in val)
            return False

        if _contains_secret(sanitized):
            return False, None

        return True, sanitized
    except Exception:
        return False, None
