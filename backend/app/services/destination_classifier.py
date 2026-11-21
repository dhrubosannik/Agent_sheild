"""Destination classification service for AgentShield."""

from typing import Any
from urllib.parse import urlsplit

from ..core.policy_models import PolicyConfiguration
from ..models.enums import DestinationClass

DESTINATION_ARGUMENT_KEYS = {
    "to",
    "recipient",
    "recipients",
    "email",
    "url",
    "destination",
    "target",
    "endpoint",
    "host",
    "hostname",
    "address",
}

INTERNAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
INTERNAL_SUFFIXES = (".internal", ".local")


def _is_approved_domain(candidate_domain: str, approved_domains: list[str]) -> bool:
    """Checks if candidate_domain matches any approved domain exactly or as a subdomain.

    Strictly prevents substring spoofing:
    - candidate: example.org, approved: example.org -> True
    - candidate: sub.example.org, approved: example.org -> True
    - candidate: example.org.attacker.test, approved: example.org -> False
    - candidate: fakeexample.org, approved: example.org -> False
    """
    cand = candidate_domain.lower().rstrip(".")
    for app in approved_domains:
        app_norm = app.lower().strip().rstrip(".")
        if cand == app_norm or cand.endswith("." + app_norm):
            return True
    return False


def _is_internal_domain(candidate_domain: str) -> bool:
    cand = candidate_domain.lower().rstrip(".")
    if cand in INTERNAL_HOSTS:
        return True
    for suffix in INTERNAL_SUFFIXES:
        if cand.endswith(suffix):
            return True
    return False


def _extract_domain(destination_str: str) -> str | None:
    """Extracts and normalizes the target domain/host from an email, URL, or host string.

    Returns None if malformed.
    """
    if not isinstance(destination_str, str):
        return None

    cleaned = destination_str.strip()
    if not cleaned:
        return None

    # 1. URL pattern
    if "://" in cleaned or cleaned.startswith(("//", "http:", "https:")):
        try:
            parsed = urlsplit(cleaned)
            hostname = parsed.hostname
            if not hostname:
                return None
            return hostname.lower().strip().rstrip(".")
        except Exception:
            return None

    # 2. Email pattern
    if "@" in cleaned:
        parts = cleaned.split("@")
        if len(parts) != 2:
            return None
        _, domain_part = parts
        domain_part = domain_part.strip().lower()
        if not domain_part or "/" in domain_part or " " in domain_part or ":" in domain_part:
            return None
        # Must have at least a dot and non-empty segments
        subparts = domain_part.split(".")
        if len(subparts) < 2 or any(not p for p in subparts):
            return None
        return domain_part.rstrip(".")

    # 3. Hostname or host:port
    host = cleaned.split(":")[0].strip().lower().rstrip(".")
    if not host or "/" in host or " " in host or "@" in host:
        return None
    return host


def _classify_single_domain(domain: str, approved_domains: list[str]) -> DestinationClass:
    if _is_internal_domain(domain):
        return DestinationClass.INTERNAL
    if _is_approved_domain(domain, approved_domains):
        return DestinationClass.APPROVED
    return DestinationClass.UNAPPROVED


def _find_destination_candidates(payload: Any) -> list[str]:
    """Recursively discovers destination strings in dictionary payloads."""
    candidates: list[str] = []

    if isinstance(payload, dict):
        for key, value in payload.items():
            if str(key).lower().strip() in DESTINATION_ARGUMENT_KEYS:
                if isinstance(value, str):
                    candidates.append(value)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, str):
                            candidates.append(item)
            elif isinstance(value, (dict, list)):
                candidates.extend(_find_destination_candidates(value))
    elif isinstance(payload, list):
        for item in payload:
            candidates.extend(_find_destination_candidates(item))

    return candidates


def classify_destination(
    arguments: dict[str, Any],
    policy: PolicyConfiguration | None = None,
) -> DestinationClass:
    """Classifies the destination of a tool call into APPROVED, UNAPPROVED, INTERNAL, or UNKNOWN.

    - Extracts destinations from relevant argument keys.
    - Handles emails and URLs safely.
    - Strictly prevents substring spoofing.
    - Returns UNKNOWN when destination is missing or malformed.
    """
    candidates = _find_destination_candidates(arguments)
    if not candidates:
        return DestinationClass.UNKNOWN

    approved_domains = policy.approved_domains if policy else []

    classes: list[DestinationClass] = []
    for candidate in candidates:
        domain = _extract_domain(candidate)
        if domain is None:
            classes.append(DestinationClass.UNKNOWN)
        else:
            classes.append(_classify_single_domain(domain, approved_domains))

    if not classes:
        return DestinationClass.UNKNOWN

    # Precedence when multiple destinations are specified:
    # 1. Any UNAPPROVED -> UNAPPROVED
    if DestinationClass.UNAPPROVED in classes:
        return DestinationClass.UNAPPROVED
    # 2. Any UNKNOWN -> UNKNOWN
    if DestinationClass.UNKNOWN in classes:
        return DestinationClass.UNKNOWN
    # 3. All INTERNAL -> INTERNAL
    if all(c == DestinationClass.INTERNAL for c in classes):
        return DestinationClass.INTERNAL
    # 4. Mix of APPROVED and INTERNAL or all APPROVED -> APPROVED
    if all(c in (DestinationClass.APPROVED, DestinationClass.INTERNAL) for c in classes):
        return DestinationClass.APPROVED

    return DestinationClass.UNKNOWN
