"""Prompt-injection risk signal heuristic detector."""

import re
from typing import Any

from ..models.risk_signal import RiskSignal

INJECTION_PATTERNS: list[tuple[str, re.Pattern[str], str, float]] = [
    (
        "INJ_IGNORE_INSTRUCTIONS",
        re.compile(
            r"(?i)\b(?:ignore\s+(?:all\s+)?previous\s+instructions|disregard\s+(?:all\s+)?prior\s+directions|forget\s+(?:all\s+)?(?:your\s+)?instructions|ignore\s+all\s+commands|system\s+override)\b"
        ),
        "Detected instruction to ignore or override prior system directions.",
        0.85,
    ),
    (
        "INJ_SECRET_DISCLOSURE",
        re.compile(
            r"(?i)\b(?:reveal\s+(?:all\s+)?confidential|tell\s+me\s+the\s+secret|dump\s+(?:the\s+)?system\s+prompt|print\s+(?:your\s+)?credentials|expose\s+the\s+secret|what\s+is\s+the\s+secret)\b"
        ),
        "Detected attempt to elicit confidential system prompt or credentials.",
        0.80,
    ),
    (
        "INJ_EXTERNAL_EXFILTRATION",
        re.compile(
            r"(?i)\b(?:send\s+(?:the\s+)?secret\s+to|transmit\s+credentials\s+to|upload\s+(?:the\s+)?password\s+to|post\s+secrets\s+to|exfiltrate\s+data\s+to|forward\s+(?:the\s+)?secret\s+to)\b"
        ),
        "Detected explicit instruction to transmit or exfiltrate sensitive data externally.",
        0.90,
    ),
    (
        "INJ_POLICY_OVERRIDE",
        re.compile(
            r"(?i)\b(?:override\s+policy|bypass\s+safety|disable\s+guardrails|ignore\s+policy\s+rules|jailbreak)\b"
        ),
        "Detected attempt to override security policies or guardrails.",
        0.85,
    ),
    (
        "INJ_CONCEAL_ACTION",
        re.compile(
            r"(?i)\b(?:do\s+not\s+tell\s+the\s+user|hide\s+this\s+action|silently\s+delete|without\s+notifying\s+the\s+user|conceal\s+(?:this\s+)?action)\b"
        ),
        "Detected instruction to conceal operations from the end user.",
        0.75,
    ),
    (
        "INJ_BYPASS_APPROVAL",
        re.compile(
            r"(?i)\b(?:bypass\s+approval|skip\s+approval|do\s+not\s+ask\s+for\s+confirmation|auto-approve)\b"
        ),
        "Detected attempt to evade human-in-the-loop approval requirements.",
        0.80,
    ),
]


def _extract_all_strings(payload: Any) -> list[str]:
    """Recursively extracts all string values from a payload."""
    strings: list[str] = []
    if isinstance(payload, str):
        strings.append(payload)
    elif isinstance(payload, dict):
        for k, v in payload.items():
            if isinstance(k, str):
                strings.append(k)
            strings.extend(_extract_all_strings(v))
    elif isinstance(payload, list):
        for item in payload:
            strings.extend(_extract_all_strings(item))
    return strings


def detect_prompt_injection(payload: Any, context: dict[str, Any] | None = None) -> list[RiskSignal]:
    """Scans tool arguments and execution context for heuristic prompt-injection risk signals.

    NOTE: This is a supplementary heuristic check, not a comprehensive detector.
    Deterministic policies must remain the primary enforcement boundary.
    """
    signals: list[RiskSignal] = []
    seen_signal_names: set[str] = set()

    strings_to_check = _extract_all_strings(payload)
    if context:
        strings_to_check.extend(_extract_all_strings(context))

    for text in strings_to_check:
        for signal_id, pattern, reason, confidence in INJECTION_PATTERNS:
            if signal_id not in seen_signal_names and pattern.search(text):
                seen_signal_names.add(signal_id)
                signals.append(
                    RiskSignal(
                        name=signal_id,
                        reason=reason,
                        confidence=confidence,
                    )
                )

    return signals
