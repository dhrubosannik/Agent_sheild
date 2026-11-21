"""Payload normalization and deterministic fingerprinting service."""

import hashlib
import json
from typing import Any

MAX_PAYLOAD_BYTES = 256 * 1024  # 256 KB
MAX_NESTING_DEPTH = 20


class NormalizationError(ValueError):
    """Raised when payload normalization fails."""


def normalize_value(value: Any, depth: int = 0) -> Any:
    """Recursively validates and normalizes payload values.

    - Rejects depths greater than MAX_NESTING_DEPTH.
    - Preserves None, booleans, and integers.
    - Rejects NaN, positive/negative infinity.
    - Normalizes strings (clean copies).
    - Recursively normalizes lists.
    - Recursively normalizes dicts, sorting string keys and stripping key whitespace.
    - Rejects non-string dict keys and non-JSON-compatible types.
    """
    if depth > MAX_NESTING_DEPTH:
        raise NormalizationError(f"Payload exceeds maximum nesting depth of {MAX_NESTING_DEPTH}")

    if value is None or isinstance(value, (bool, int)):
        return value

    if isinstance(value, float):
        if value != value:  # NaN
            raise NormalizationError("Payload cannot contain NaN values")
        if value in (float("inf"), float("-inf")):
            raise NormalizationError("Payload cannot contain infinite values")
        return value

    if isinstance(value, str):
        return value

    if isinstance(value, list):
        return [normalize_value(item, depth + 1) for item in value]

    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key in sorted(value.keys(), key=lambda k: str(k)):
            if not isinstance(key, str):
                raise NormalizationError("Payload dictionary keys must be strings")
            clean_key = key.strip()
            if not clean_key:
                raise NormalizationError("Payload dictionary keys cannot be empty or blank")
            normalized[clean_key] = normalize_value(value[key], depth + 1)
        return normalized

    raise NormalizationError(f"Unsupported payload value type: {type(value).__name__}")


def normalize_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    """Validates and normalizes tool call arguments dictionary."""
    if not isinstance(arguments, dict):
        raise NormalizationError("Arguments must be a dictionary")

    normalized = normalize_value(arguments)

    try:
        encoded = json.dumps(normalized, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise NormalizationError("Failed to serialize arguments to JSON") from exc

    if len(encoded.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        raise NormalizationError(f"Payload size exceeds maximum allowed size of {MAX_PAYLOAD_BYTES} bytes")

    return normalized


def compute_payload_fingerprint(payload: Any) -> str:
    """Generates a deterministic SHA-256 fingerprint for a payload.

    Equivalent normalized payloads produce the exact same fingerprint.
    """
    normalized = normalize_value(payload)
    serialized = json.dumps(normalized, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"
