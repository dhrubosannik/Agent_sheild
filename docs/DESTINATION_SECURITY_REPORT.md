# Destination Security Report (Phase 13.2, Priority 2)

## Finding 2.1: Internal and sensitive destinations allowed by default. **PASS**

**Original vulnerability.** `localhost`, `127.0.0.1`, `*.internal` and `*.local` were classified INTERNAL, and INTERNAL was **allowed by default**. Confirmed: `http_post` to `http://metadata.google.internal/computeMetadata/v1/` (the GCP credentials endpoint) and to `http://localhost:8080/admin` both returned ALLOW. Private ranges, link-local addresses, IPv6 local forms and numeric IP encodings were not recognized at all.

**Root cause.** In `policy_evaluator.py` the default branch treated `INTERNAL` like `APPROVED`. Separately, the internal check was a short hostname list with no IP parsing.

**Files changed**
- `backend/app/services/destination_classifier.py` (rewritten)
- `backend/app/services/policy_evaluator.py`
- `backend/app/core/policy_models.py`

**Fix implemented**
- **IP normalization** (`parse_ip`):
  - IPv6, bracketed forms and zone IDs;
  - IPv4-mapped, 6to4, Teredo and NAT64 addresses, unwrapped to the embedded IPv4;
  - every IPv4 spelling the OS accepts (`127.1`, `2130706433`, `0x7f000001`, `0177.0.0.1`);
  - ambiguous numeric hosts (for example `1.2.3.4.5`) are UNKNOWN.
- **Internal reasons:**
  - `CLOUD_METADATA_ENDPOINT`: 169.254.169.254, 169.254.170.2, 100.100.100.200, 192.0.0.192, fd00:ec2::254, `metadata`, `metadata.google.internal`, `instance-data`;
  - loopback, link-local, private (RFC 1918, ULA `fc00::/7`), unspecified, multicast, any other non-global range (including CGNAT 100.64/10);
  - internal hostnames: `localhost`, `*.localhost`, `.local`, `.internal`, `.intranet`, `.lan`, `.home.arpa`, `.corp`, `.private`, `.svc`, `.cluster.local`;
  - single-label service names such as `redis` or `kubernetes`.
- **Decision.** INTERNAL is evaluated immediately after explicit BLOCK rules, so no redact, approval or allow rule can permit it. The decision is `defaults.internal_destination`, which defaults to BLOCK. The policy model only accepts BLOCK or REQUIRE_APPROVAL there; ALLOW is rejected.
- **Explicit allowlist.** New field `allowed_internal_destinations` accepts exact hosts, IPs or CIDRs; wildcards are rejected. Matching destinations are classified APPROVED. Nothing else internal is permitted.

**Tests executed.** `backend/tests/test_destination_security.py`:
- 27 internal URLs × 2: classified INTERNAL, and evaluated to BLOCK;
- the default can be approval, but ALLOW is rejected;
- the allowlist permits only the listed targets;
- 8 public-destination cases;
- the four bypasses from the original review, against the real default policy.

All pass.

**Remaining limitations**
- Hostname checks are name-based. A public DNS name that *resolves* to an internal address is caught only at connection time (Finding 2.3).
- Single-label names count as internal. For non-network schemes such as `s3://bucket` the host is a bucket name, so the single-label rule is not applied and the result is UNKNOWN.

## Finding 2.2: Destinations discovered only by argument name. **PASS**

**Original vulnerability.** Only fixed keys (`to`, `url`, `email` …) were inspected. `{"to": "colleague@example.org", "bcc": "attacker@evil.net"}` and `webhook_url: https://evil.net` were both ALLOWED.

**Root cause.** `_find_destination_candidates` matched a fixed key set and ignored all other values.

**Fix implemented**
- **Recursive value-based detection** at any depth, in dicts and lists. A string value counts as a destination when it is *in its entirety* one of: a URL (any scheme, or `//host`), an email address, a `mailto:` list, an IP literal (canonical spelling), a `host:port` pair, or a well-known internal or metadata hostname.
- **Key-based detection.** Keys are tokenized (`webhookURL` → `webhook`, `url`). Destination-like tokens include `to`, `cc`, `bcc`, `recipient`, `url`, `uri`, `host`, `endpoint`, `webhook`, `callback`, `server`, `target`, `proxy` and others. Under such keys, bare hostnames and legacy numeric IP forms are also treated as destinations, and unparseable values fail closed to UNKNOWN.
- **Avoiding false positives:**
  - free text that merely *contains* a URL or address (for example an email body) is content, not a destination;
  - version strings such as `1.2.3` are not IPs outside destination keys;
  - sender emails under `from` or `sender` are ignored. A URL or IP under those keys is still classified.
- **Fail closed for ambiguous URLs** (result UNKNOWN): backslashes, whitespace or control characters (parser differentials such as `https://evil.test\@example.org`), userinfo (`https://example.org@evil.net`), invalid ports, percent-encoded hosts, and URLs without a host (`file:///…`).
- **Precedence across all destinations of one call:** INTERNAL > UNAPPROVED > UNKNOWN > APPROVED.

**Tests executed.** In `test_destination_security.py`:
- alternate and nested names: 7 cases (`bcc`, `webhook_url`, `callbackUrl`, nested dict, nested list, `host:port`, `mailto:`);
- a nested internal endpoint, with its reported location;
- 11 malformed or ambiguous values;
- 5 false-positive guards.

The existing `test_destination_classifier.py` still passes. All pass.

**Remaining limitations**
- A destination hidden inside free text, encoded (base64, split across fields) or computed later by the tool is not detected. Argument inspection cannot see how a tool *uses* a value.
- A four-part version string such as `"1.2.3.4"` is a canonical IPv4 address and is classified as a public IP destination: a documented false positive.

## Finding 2.3: No connection-time validation (DNS rebinding). **PARTIAL**

**Original vulnerability.** Evaluation checks names, but tools connect later. A name can resolve to an internal IP, or change its answer between evaluation and connection.

**Fix implemented.** New `backend/app/services/safe_network.py`, re-exported as `sdk/agentshield/network.py`:
- `resolve_and_validate()` resolves once and fails closed in each of these cases: any resolved address is internal (a mixed public and private answer counts as a rebinding pattern), resolution fails, or the name is malformed or internal.
- `create_guarded_client()` returns an `httpx.Client` whose transport uses `GuardedNetworkBackend`. Every connection, including each redirect hop, is resolved and validated, then the socket is opened **to the validated IP**, so the OS never performs a second lookup. TLS verification and SNI still use the original hostname.
- Environment proxies are disabled, because a proxy would resolve names outside AgentShield's control.
- Unix sockets are refused.
- Evaluation itself performs no DNS lookups, by design: any answer it got could change before connection.

**Tests executed** (all pass):
- internal answer refused;
- mixed answer refused;
- IPv6 link-local answer refused;
- unresolvable name refused;
- public answer accepted;
- **a real local HTTP server**: loopback refused; an attacker name resolving to loopback refused; an allowlisted name connects with exactly one resolution and the original `Host` header;
- a redirect to 169.254.169.254 refused;
- proxies disabled.

**Why PARTIAL**
- Protection applies only to network calls made **through the guarded client**. AgentShield does not intercept sockets opened by other libraries; tool authors must adopt `create_guarded_client()`.
- Only a synchronous client is provided; there is no async variant yet.
- The demo's mock tools make no network calls.
