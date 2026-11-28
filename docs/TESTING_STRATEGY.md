# Testing Strategy

## Test levels
- Unit tests for normalization, destination classification, sensitive-data detection, policy matching, redaction, and decision precedence.
- SDK tests proving protected tool execution behavior.
- API tests for valid/invalid requests, event listing, and approval decisions.
- Integration tests for the full demo flow.
- Frontend smoke tests if a React dashboard is used.

## Required synthetic scenarios
1. **Benign allowed action:** approved destination, no protected data → ALLOW.
2. **Secret exfiltration:** `DEMO_SECRET` sent to unapproved external destination → BLOCK.
3. **Redaction:** a policy-designated field is masked before tool execution → REDACT.
4. **Approval:** external export or high-impact operation → REQUIRE_APPROVAL.
5. **Unknown destination:** must follow configured safe default.
6. **Indirect injection signal:** malicious vendor document contains instructions to ignore prior rules and disclose secrets; record a risk signal. The deterministic data/destination policy must still block the exfiltration attempt.
7. **Domain spoofing:** `approved.example.attacker.test` must not be classified as approved merely because it contains an approved-domain substring.
8. **Malformed policy:** startup/evaluation must fail safely.
9. **Audit privacy:** confirm raw canary secrets do not appear in stored audit records.
10. **Tool non-execution:** blocked and approval-required calls never invoke the underlying function.

## Metrics to report
- Policy correctness count on the versioned synthetic scenario pack
- Unsafe scenarios blocked
- False blocks on benign scenarios
- Wrapped-tool coverage
- p50/p95 evaluation overhead if time permits

Do not claim real-world detection accuracy from a tiny synthetic pack.
