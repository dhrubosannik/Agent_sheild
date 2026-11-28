"""Connection-time destination enforcement (DNS-rebinding defence).

Policy evaluation classifies the destination *names* in tool arguments, but a
public-looking name can resolve to an internal address, and the answer can
change between evaluation and connection (DNS rebinding). Tools that make
network requests must therefore validate the addresses they actually connect
to. This module provides:

* ``resolve_and_validate(host, port)``: resolves once, rejects the destination
  if *any* resolved address is internal/sensitive (unless allowlisted), and
  returns the validated addresses.
* ``create_guarded_client()``: an ``httpx.Client`` whose transport resolves
  and validates every connection (including redirects) and then connects to
  the already-validated IP, so the operating system never performs a second,
  attacker-influenced lookup. TLS certificate verification and SNI still use
  the original hostname.

Limitation: protection only applies to network calls made through these
helpers. A tool that opens sockets by other means is not covered.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
import ipaddress
import socket
import ssl
from typing import Any

import certifi
import httpcore
import httpx

from ..core.policy_models import PolicyConfiguration
from .destination_classifier import (
    hostname_internal_reason,
    ip_internal_reason,
    normalize_hostname,
    parse_ip,
)

Resolver = Callable[..., list[tuple[Any, ...]]]


class DestinationNotPermittedError(ConnectionError):
    """Raised when a connection target is internal, sensitive or unresolvable."""

    def __init__(self, host: str, reason: str) -> None:
        super().__init__(f"Connection to '{host}' refused by AgentShield: {reason}")
        self.host = host
        self.reason = reason


def _allowlisted(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, host: str | None, allowlist: Iterable[str]) -> bool:
    for entry in allowlist:
        try:
            if ip in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            if host is not None and host == entry:
                return True
    return False


def resolve_and_validate(
    host: str,
    port: int,
    policy: PolicyConfiguration | None = None,
    resolver: Resolver = socket.getaddrinfo,
) -> list[str]:
    """Resolves ``host`` once and returns its addresses if all are permitted.

    Fails closed: unresolvable names, malformed names and any internal address
    in the answer set (a mixed public/private answer is a rebinding pattern)
    raise ``DestinationNotPermittedError``.
    """
    allowlist = policy.allowed_internal_destinations if policy else []

    try:
        literal = parse_ip(host)
    except ValueError:
        raise DestinationNotPermittedError(host, "AMBIGUOUS_NUMERIC_HOST")

    if literal is not None:
        reason = ip_internal_reason(literal)
        if reason and not _allowlisted(literal, None, allowlist):
            raise DestinationNotPermittedError(host, reason)
        return [str(literal)]

    normalized = normalize_hostname(host)
    if normalized is None:
        raise DestinationNotPermittedError(host, "MALFORMED_HOST")

    name_reason = hostname_internal_reason(normalized)
    if name_reason and normalized not in allowlist:
        raise DestinationNotPermittedError(host, name_reason)

    try:
        infos = resolver(normalized, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise DestinationNotPermittedError(host, f"DNS_RESOLUTION_FAILED ({exc.__class__.__name__})")

    addresses: list[str] = []
    for info in infos:
        raw = info[4][0]
        try:
            ip = ipaddress.ip_address(str(raw).split("%", 1)[0])
        except ValueError:
            raise DestinationNotPermittedError(host, "UNPARSEABLE_RESOLVED_ADDRESS")
        reason = ip_internal_reason(ip)
        if reason and not _allowlisted(ip, normalized, allowlist):
            raise DestinationNotPermittedError(host, f"RESOLVES_TO_{reason}")
        if str(ip) not in addresses:
            addresses.append(str(ip))

    if not addresses:
        raise DestinationNotPermittedError(host, "NO_ADDRESSES_RESOLVED")
    return addresses


class GuardedNetworkBackend(httpcore.NetworkBackend):
    """httpcore backend that validates and pins resolved addresses."""

    def __init__(
        self,
        policy: PolicyConfiguration | None = None,
        resolver: Resolver = socket.getaddrinfo,
        inner: httpcore.NetworkBackend | None = None,
    ) -> None:
        self._policy = policy
        self._resolver = resolver
        self._inner = inner or httpcore.SyncBackend()

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.NetworkStream:
        addresses = resolve_and_validate(host, port, self._policy, self._resolver)
        last_error: Exception | None = None
        for address in addresses:
            try:
                return self._inner.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, OSError) as exc:
                last_error = exc
        raise httpcore.ConnectError(f"Unable to connect to any validated address for {host}") from last_error

    def connect_unix_socket(self, *args: Any, **kwargs: Any) -> httpcore.NetworkStream:
        raise DestinationNotPermittedError("unix-socket", "UNIX_SOCKETS_NOT_PERMITTED")

    def sleep(self, seconds: float) -> None:
        self._inner.sleep(seconds)


class GuardedTransport(httpx.BaseTransport):
    """httpx transport using ``GuardedNetworkBackend`` for every connection."""

    def __init__(
        self,
        policy: PolicyConfiguration | None = None,
        resolver: Resolver = socket.getaddrinfo,
        ssl_context: ssl.SSLContext | None = None,
        inner_backend: httpcore.NetworkBackend | None = None,
    ) -> None:
        self.network_backend = GuardedNetworkBackend(policy, resolver, inner_backend)
        self._pool = httpcore.ConnectionPool(
            ssl_context=ssl_context or ssl.create_default_context(cafile=certifi.where()),
            network_backend=self.network_backend,
        )

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        try:
            core_response = self._pool.handle_request(core_request)
        except httpcore.ConnectError as exc:
            if isinstance(exc.__cause__, DestinationNotPermittedError):
                raise exc.__cause__
            raise httpx.ConnectError(str(exc), request=request) from exc

        return httpx.Response(
            status_code=core_response.status,
            headers=core_response.headers,
            stream=_ResponseStream(core_response),
            extensions=core_response.extensions,
        )

    def close(self) -> None:
        self._pool.close()


class _ResponseStream(httpx.SyncByteStream):
    def __init__(self, response: httpcore.Response) -> None:
        self._response = response

    def __iter__(self):
        yield from self._response.iter_stream()

    def close(self) -> None:
        self._response.close()


def create_guarded_client(
    policy: PolicyConfiguration | None = None,
    resolver: Resolver = socket.getaddrinfo,
    **client_kwargs: Any,
) -> httpx.Client:
    """Returns an httpx.Client that refuses internal/sensitive destinations at
    connection time. Environment proxies are disabled (a proxy would perform
    resolution outside AgentShield's control) and redirects are off by
    default; when enabled, every redirect hop is validated again."""
    client_kwargs.setdefault("follow_redirects", False)
    client_kwargs["trust_env"] = False
    return httpx.Client(transport=GuardedTransport(policy, resolver), **client_kwargs)
