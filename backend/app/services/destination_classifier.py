"""Destination classification service for AgentShield.

Destinations are discovered by *value* as well as by argument name:

* Any string value (at any nesting depth, under any key) that is in its
  entirety a URL, an email address, a ``mailto:`` link, an IP literal, a
  ``host:port`` pair or a well-known internal hostname is a destination.
* Under destination-like keys (``to``, ``bcc``, ``webhook_url``, ``host`` ...)
  bare hostnames are destinations too, and values that cannot be parsed fail
  closed to UNKNOWN.
* Free text that merely *contains* a URL or address (for example an email
  body) is content, not a destination, and is not classified.

Classification precedence across all destinations of one call:
INTERNAL > UNAPPROVED > UNKNOWN > APPROVED.

Evaluation never performs DNS lookups: a name that resolves to an internal
address is caught at connection time by ``safe_network`` (DNS-rebinding
defence), because any resolution performed here could change before the tool
connects.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
import socket
from typing import Any
from urllib.parse import urlsplit

from ..core.policy_models import PolicyConfiguration
from ..models.enums import DestinationClass

# Tokens that mark an argument name as destination-bearing. Keys are split on
# non-alphanumerics and camelCase boundaries ("webhookURL" -> webhook, url).
DESTINATION_KEY_TOKENS = {
    "to", "cc", "bcc", "recipient", "recipients", "email", "emails", "mail",
    "url", "urls", "uri", "uris", "link", "href", "host", "hosts", "hostname",
    "domain", "domains", "endpoint", "endpoints", "address", "addresses",
    "destination", "destinations", "target", "targets", "webhook", "webhooks",
    "callback", "server", "servers", "remote", "upstream", "proxy", "mailto",
    "ip", "addr", "dest", "dst", "sink", "forward",
}
# Sender-side fields are not destinations.
NON_DESTINATION_KEY_TOKENS = {"from", "sender", "author", "source", "src", "origin"}

# Schemes whose host we can meaningfully classify as an approved web/mail peer.
NETWORK_SCHEMES = {"http", "https", "ws", "wss", "ftp", "ftps", "sftp", "smtp", "smtps"}

INTERNAL_HOSTNAMES = {
    "localhost",
    "metadata",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "instance-data.ec2.internal",
    "kubernetes",
    "kubernetes.default",
    "kubernetes.default.svc",
}
INTERNAL_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".intranet",
    ".lan",
    ".home.arpa",
    ".corp",
    ".private",
    ".svc",
    ".cluster.local",
)
# Explicit cloud-metadata IPs (most are already non-global, listed for clarity).
METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("169.254.170.2"),
    ipaddress.ip_address("100.100.100.200"),
    ipaddress.ip_address("192.0.0.192"),
    ipaddress.ip_address("fd00:ec2::254"),
}

_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")
_EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~\-]+@(?P<domain>[^@\s]+)$")
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_NUMERIC_LABEL_RE = re.compile(r"^(0x[0-9a-f]*|[0-9]+)$")
_HOST_PORT_RE = re.compile(r"^(?P<host>[A-Za-z0-9.\-]+):(?P<port>[0-9]{1,5})$")
_BRACKET_HOST_RE = re.compile(r"^\[(?P<host>[^\]]+)\](?::(?P<port>[0-9]{1,5}))?$")
_FORBIDDEN_CHARS_RE = re.compile(r"[\s\\\x00-\x1f\x7f]")
_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


@dataclass(frozen=True)
class DestinationFinding:
    """One destination discovered in tool arguments (never holds payload data
    beyond the normalized host)."""

    location: str
    host: str | None
    destination_class: DestinationClass
    reason: str


# --------------------------------------------------------------------------- #
# Host normalization
# --------------------------------------------------------------------------- #

def _key_tokens(key: str) -> set[str]:
    spaced = _CAMEL_RE.sub(" ", key)
    return {token for token in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if token}


def _is_destination_key(key: str) -> bool:
    tokens = _key_tokens(key)
    if tokens & NON_DESTINATION_KEY_TOKENS:
        return False
    return bool(tokens & DESTINATION_KEY_TOKENS)


def parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parses canonical and legacy IP spellings.

    Accepts IPv6 (optionally bracketed or with a zone id) and every IPv4 form
    that ``inet_aton`` accepts (``127.1``, ``0x7f.0.0.1``, ``2130706433``,
    octal), because HTTP clients and the OS resolver accept them too.
    """
    candidate = host.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    candidate = candidate.split("%", 1)[0]  # drop IPv6 zone id
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        pass
    labels = candidate.lower().split(".")
    if labels and all(_NUMERIC_LABEL_RE.match(label) for label in labels if label) and all(labels):
        try:
            return ipaddress.IPv4Address(socket.inet_aton(candidate))
        except OSError:
            raise ValueError(f"ambiguous numeric host: {host!r}")
    return None


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip.teredo is not None:
        return ip.teredo[1]
    if ip in ipaddress.ip_network("64:ff9b::/96"):
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def ip_internal_reason(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Returns a reason code when an IP is not a public, routable address."""
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(ip)
        if embedded is not None:
            reason = ip_internal_reason(embedded)
            if reason:
                return reason
    if ip in METADATA_IPS:
        return "CLOUD_METADATA_ENDPOINT"
    if ip.is_loopback:
        return "LOOPBACK_ADDRESS"
    if ip.is_link_local:
        return "LINK_LOCAL_ADDRESS"
    if ip.is_unspecified:
        return "UNSPECIFIED_ADDRESS"
    if ip.is_multicast:
        return "MULTICAST_ADDRESS"
    if ip.is_private:
        return "PRIVATE_NETWORK_ADDRESS"
    if not ip.is_global:
        return "NON_GLOBAL_ADDRESS"
    return None


def normalize_hostname(host: str) -> str | None:
    """Lowercases, strips a trailing dot and IDNA-encodes a hostname.

    Returns None when the name is not a syntactically valid DNS hostname.
    """
    cleaned = host.strip().rstrip(".")
    if not cleaned or _FORBIDDEN_CHARS_RE.search(cleaned) or "%" in cleaned:
        return None
    try:
        ascii_host = cleaned.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if len(ascii_host) > 253:
        return None
    labels = ascii_host.split(".")
    if not all(_LABEL_RE.match(label) for label in labels):
        return None
    return ascii_host


def hostname_internal_reason(host: str) -> str | None:
    if host in {"metadata", "metadata.google.internal", "metadata.goog", "instance-data", "instance-data.ec2.internal"}:
        return "CLOUD_METADATA_ENDPOINT"
    if host in INTERNAL_HOSTNAMES:
        return "INTERNAL_HOSTNAME"
    if any(host.endswith(suffix) for suffix in INTERNAL_SUFFIXES):
        return "INTERNAL_HOSTNAME"
    if "." not in host:
        # Single-label names resolve through search domains to internal services.
        return "INTERNAL_SERVICE_NAME"
    return None


def _is_allowlisted(host: str, ip: Any, allowlist: list[str]) -> bool:
    for entry in allowlist:
        if ip is not None:
            try:
                if ip in ipaddress.ip_network(entry, strict=False):
                    return True
                continue
            except ValueError:
                pass
        if host == entry:
            return True
    return False


def _is_approved_domain(candidate_domain: str, approved_domains: list[str]) -> bool:
    """Exact or subdomain match; prevents substring spoofing
    (``example.org.attacker.test`` and ``fakeexample.org`` are not approved)."""
    cand = candidate_domain.lower().rstrip(".")
    for app in approved_domains:
        app_norm = app.lower().strip().rstrip(".")
        if cand == app_norm or cand.endswith("." + app_norm):
            return True
    return False


def classify_host(
    host: str,
    approved_domains: list[str],
    allowed_internal: list[str],
    *,
    allow_single_label: bool = False,
) -> tuple[DestinationClass, str, str | None]:
    """Classifies one host. Returns (class, reason, normalized_host)."""
    try:
        ip = parse_ip(host)
    except ValueError:
        return DestinationClass.UNKNOWN, "AMBIGUOUS_NUMERIC_HOST", None

    if ip is not None:
        normalized = str(ip)
        reason = ip_internal_reason(ip)
        if reason:
            if _is_allowlisted(normalized, ip, allowed_internal):
                return DestinationClass.APPROVED, "ALLOWLISTED_INTERNAL_DESTINATION", normalized
            return DestinationClass.INTERNAL, reason, normalized
        # Public IP literals are never matched against approved *domains*.
        if _is_allowlisted(normalized, ip, allowed_internal):
            return DestinationClass.APPROVED, "ALLOWLISTED_DESTINATION", normalized
        return DestinationClass.UNAPPROVED, "PUBLIC_IP_LITERAL", normalized

    normalized = normalize_hostname(host)
    if normalized is None:
        return DestinationClass.UNKNOWN, "MALFORMED_HOST", None

    reason = hostname_internal_reason(normalized)
    if reason == "INTERNAL_SERVICE_NAME" and allow_single_label:
        reason = None
    if reason:
        if _is_allowlisted(normalized, None, allowed_internal):
            return DestinationClass.APPROVED, "ALLOWLISTED_INTERNAL_DESTINATION", normalized
        return DestinationClass.INTERNAL, reason, normalized
    if _is_approved_domain(normalized, approved_domains):
        return DestinationClass.APPROVED, "APPROVED_DOMAIN", normalized
    return DestinationClass.UNAPPROVED, "UNAPPROVED_DOMAIN", normalized


# --------------------------------------------------------------------------- #
# Value parsing
# --------------------------------------------------------------------------- #

def _looks_like_destination(value: str) -> bool:
    """True when the whole string is destination-shaped, regardless of key."""
    if _SCHEME_RE.match(value) or value.startswith("//") or value.lower().startswith("mailto:"):
        return True
    if _EMAIL_RE.match(value):
        return True
    if _BRACKET_HOST_RE.match(value):
        return True
    # Outside destination keys only canonical IP spellings count, so version
    # strings such as "1.2.3" (which inet_aton would accept) are not flagged.
    if _is_canonical_ip(value):
        return True
    match = _HOST_PORT_RE.match(value)
    if match:
        if _is_canonical_ip(match.group("host")):
            return True
        if "." in match.group("host") and normalize_hostname(match.group("host")) and not _is_numeric_dotted(match.group("host")):
            return True
    host = normalize_hostname(value)
    if host is not None and hostname_internal_reason(host) in {"CLOUD_METADATA_ENDPOINT", "INTERNAL_HOSTNAME"}:
        return True
    return False


def _is_canonical_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.split("%", 1)[0])
        return True
    except ValueError:
        return False


def _is_numeric_dotted(value: str) -> bool:
    return all(part.isdigit() for part in value.split("."))


def _classify_url(value: str, approved: list[str], allowed: list[str]) -> tuple[DestinationClass, str, str | None]:
    if _FORBIDDEN_CHARS_RE.search(value):
        # Backslashes/whitespace are parsed differently by different URL
        # parsers (e.g. "https://evil.test\@example.org").
        return DestinationClass.UNKNOWN, "AMBIGUOUS_URL", None
    try:
        parsed = urlsplit(value if not value.startswith("//") else "https:" + value)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc
        if not netloc:
            return DestinationClass.UNKNOWN, "URL_WITHOUT_HOST", None
        if "@" in netloc:
            return DestinationClass.UNKNOWN, "URL_USERINFO_NOT_PERMITTED", None
        hostname = parsed.hostname
        _ = parsed.port  # raises ValueError for invalid ports
    except ValueError:
        return DestinationClass.UNKNOWN, "MALFORMED_URL", None
    if not hostname:
        return DestinationClass.UNKNOWN, "URL_WITHOUT_HOST", None

    dest_class, reason, host = classify_host(
        hostname, approved, allowed, allow_single_label=scheme not in NETWORK_SCHEMES
    )
    if dest_class == DestinationClass.INTERNAL:
        return dest_class, reason, host
    if scheme not in NETWORK_SCHEMES:
        return DestinationClass.UNKNOWN, "UNSUPPORTED_URL_SCHEME", host
    return dest_class, reason, host


def _classify_email(value: str, approved: list[str], allowed: list[str]) -> tuple[DestinationClass, str, str | None]:
    match = _EMAIL_RE.match(value)
    if not match:
        return DestinationClass.UNKNOWN, "MALFORMED_EMAIL", None
    domain = match.group("domain")
    if domain.startswith("[") and domain.endswith("]"):
        inner = domain[1:-1]
        if inner.lower().startswith("ipv6:"):
            inner = inner[5:]
        return classify_host(inner, approved, allowed)
    if "." not in domain.rstrip("."):
        host = normalize_hostname(domain)
        if host is None:
            return DestinationClass.UNKNOWN, "MALFORMED_EMAIL", None
        return classify_host(host, approved, allowed)
    return classify_host(domain, approved, allowed)


def classify_destination_value(
    value: str,
    approved_domains: list[str],
    allowed_internal: list[str],
) -> tuple[DestinationClass, str, str | None]:
    """Classifies a single destination string (URL, email, host, IP)."""
    cleaned = value.strip()
    if not cleaned:
        return DestinationClass.UNKNOWN, "EMPTY_DESTINATION", None

    if cleaned.lower().startswith("mailto:"):
        addresses = cleaned[7:].split("?", 1)[0]
        results = [
            _classify_email(addr.strip(), approved_domains, allowed_internal)
            for addr in addresses.split(",")
            if addr.strip()
        ]
        if not results:
            return DestinationClass.UNKNOWN, "MALFORMED_EMAIL", None
        return _most_restrictive(results)

    if _SCHEME_RE.match(cleaned) or cleaned.startswith("//"):
        return _classify_url(cleaned, approved_domains, allowed_internal)

    if "@" in cleaned:
        return _classify_email(cleaned, approved_domains, allowed_internal)

    bracket = _BRACKET_HOST_RE.match(cleaned)
    if bracket:
        return classify_host(bracket.group("host"), approved_domains, allowed_internal)

    host_port = _HOST_PORT_RE.match(cleaned)
    if host_port:
        if not 0 < int(host_port.group("port")) <= 65535:
            return DestinationClass.UNKNOWN, "INVALID_PORT", None
        return classify_host(host_port.group("host"), approved_domains, allowed_internal)

    if "/" in cleaned:
        # "example.org/path" without a scheme: classify the host part.
        host_part = cleaned.split("/", 1)[0]
        if not host_part:
            return DestinationClass.UNKNOWN, "MALFORMED_DESTINATION", None
        return classify_host(host_part, approved_domains, allowed_internal)

    return classify_host(cleaned, approved_domains, allowed_internal)


_PRECEDENCE = [
    DestinationClass.INTERNAL,
    DestinationClass.UNAPPROVED,
    DestinationClass.UNKNOWN,
    DestinationClass.APPROVED,
]


def _most_restrictive(results: list[tuple[DestinationClass, str, str | None]]) -> tuple[DestinationClass, str, str | None]:
    return min(results, key=lambda item: _PRECEDENCE.index(item[0]))


# --------------------------------------------------------------------------- #
# Payload traversal
# --------------------------------------------------------------------------- #

def _collect(
    payload: Any,
    location: str,
    under_destination_key: bool,
    approved: list[str],
    allowed: list[str],
    findings: list[DestinationFinding],
    depth: int = 0,
    sender_key: bool = False,
) -> None:
    if depth > 32:
        findings.append(DestinationFinding(location, None, DestinationClass.UNKNOWN, "MAX_DEPTH_EXCEEDED"))
        return
    if isinstance(payload, dict):
        for key, value in payload.items():
            key_str = str(key)
            child = f"{location}.{key_str}" if location else key_str
            _collect(
                value,
                child,
                _is_destination_key(key_str),
                approved,
                allowed,
                findings,
                depth + 1,
                sender_key=bool(_key_tokens(key_str) & NON_DESTINATION_KEY_TOKENS),
            )
    elif isinstance(payload, list):
        for index, item in enumerate(payload):
            _collect(item, f"{location}[{index}]", under_destination_key, approved, allowed, findings, depth + 1, sender_key)
    elif isinstance(payload, str):
        value = payload.strip()
        if not value:
            return
        if sender_key and _EMAIL_RE.match(value):
            return  # sender address (from/sender), not a destination
        if under_destination_key or _looks_like_destination(value):
            dest_class, reason, host = classify_destination_value(value, approved, allowed)
            findings.append(DestinationFinding(location or "payload", host, dest_class, reason))


def find_destinations(
    arguments: dict[str, Any],
    policy: PolicyConfiguration | None = None,
) -> list[DestinationFinding]:
    approved = policy.approved_domains if policy else []
    allowed = policy.allowed_internal_destinations if policy else []
    findings: list[DestinationFinding] = []
    _collect(arguments, "", False, approved, allowed, findings)
    return findings


def summarize_findings(findings: list[DestinationFinding]) -> DestinationClass:
    if not findings:
        return DestinationClass.UNKNOWN
    classes = {finding.destination_class for finding in findings}
    for candidate in _PRECEDENCE:
        if candidate in classes:
            return candidate
    return DestinationClass.UNKNOWN


def classify_destination(
    arguments: dict[str, Any],
    policy: PolicyConfiguration | None = None,
) -> DestinationClass:
    """Classifies the destinations of a tool call into APPROVED, UNAPPROVED,
    INTERNAL or UNKNOWN (UNKNOWN when no destination is present or one cannot
    be parsed safely)."""
    return summarize_findings(find_destinations(arguments, policy))
