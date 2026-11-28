# Remaining Risks (after Phase 13.2)

These are known gaps that Phase 13.2 did **not** close, or closed only partly. Nothing here should be described as solved in presentations or judge Q&A.

## High

1. **The SDK is a guardrail, not a security boundary.** The SDK evaluates policy *inside the agent's own Python process*. Code running in that runtime can:
   - call the original function (`tool.__wrapped__`);
   - mutate `shield.policy`;
   - monkeypatch `shield.evaluate_tool_call`;
   - continue after audit persistence fails.

   `sdk/tests/test_sdk_boundary.py` asserts that each of these bypasses works, so they stay documented. Enforcement against a malicious or compromised agent requires running tools in a separate process or service that the agent cannot modify, which calls `POST /api/v1/evaluate` and holds the credentials the tools need. That architecture is not implemented.

2. **Connection-time destination checks are opt-in.** `create_guarded_client()` prevents DNS rebinding only for requests made through it. Tools using `requests`, raw sockets or other clients are not covered, and no async client is provided.

3. **Privileged Firestore access can rewrite history.** The Admin SDK, service-account holders and console users bypass Security Rules. Tampering, deletion and truncation are *detected* by the chain, sequence ledger and head document. However, an attacker who rewrites records **and** the head consistently is not detected. That needs externally published, signed checkpoints; the signing helpers exist but there is no checkpoint publication or schedule.

## Medium

4. **Audit throughput is bounded.** The single global chain serializes all appends on one Firestore head document. A per-process lock removes in-instance contention, but cross-instance throughput is bounded by Firestore's per-document write rate. Very high event rates would need sharded chains.

5. **Rate limiting.**
   - The Firestore limiter adds one transaction per request (latency and cost), and is shared per IP key. A flood from one IP across instances can exhaust transaction retries. That fails **closed** (503) by default (`RATE_LIMIT_FAIL_OPEN=false`).
   - `TRUSTED_PROXY_COUNT=1` for Render is an assumption that was **not tested on Render**. If the hop count is wrong, either every client shares one key or `X-Forwarded-For` becomes spoofable.
   - The Firestore TTL policy for `rate_limits.expires_at` is declared in `firestore.indexes.json` but not deployed.

6. **Firestore composite indexes are declared, not proven.** `firestore.indexes.json` was derived from the actual queries. The emulator does not enforce composite indexes, and nothing was deployed, so a missing index would surface as a `FAILED_PRECONDITION` error on the first production query.

7. **Detection of destinations and secrets is pattern-based.**
   - Destinations encoded, split or computed by the tool, or embedded in free text, are not found.
   - Protected values are matched exactly: case changes or base64 evade detection. These are blocked today only when the destination is also unapproved.
   - Prompt-injection detection is a weak heuristic.

8. **No separation of duties for approvals.** A REVIEWER can approve an action they triggered. Approvals also do not re-execute the tool.

9. **Open self-registration.** Any verified email address becomes a VIEWER, who can read all events and run demo scenarios (which write events).

## Low

10. `/docs` uses a CSP with `'unsafe-inline'` scripts, scoped to the documentation pages only. API responses keep `default-src 'none'`. Swagger rendering in a real browser was **not tested**. Disabling docs in production is an option.
11. A four-part version string (for example `"1.2.3.4"`) in an argument is classified as a public IP destination (false positive, fails safe).
12. Development identities are accepted from loopback only, but anyone with local shell access to a dev machine can use them. Production refuses to start if `DEV_AUTH_IDENTITIES` is set.
13. The local `data/agentshield.db` contains 168 v2 test records written by the test suite before it was isolated. See `AUDIT_INTEGRITY_REPORT.md`.
14. `scripts/emulator_test_results.json` and `scripts/e2e_test_results.json` are tracked files that the verification scripts overwrite on each run.
