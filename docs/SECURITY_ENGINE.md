# Security Engine Specification

## Purpose
Inspect proposed tool calls before execution and produce explainable risk findings.

## Deterministic enforcement checks
These are the primary controls:
1. Is the tool allowed by policy?
2. Is the action type allowed?
3. Is the destination approved, denied, internal, or external?
4. Does the payload contain configured protected values or sensitive-data patterns?
5. Does policy require approval for this tool, destination, or data class?
6. Is the proposed payload compatible with the tool's allowed schema?

## Heuristic risk signals
Optional supplementary checks may flag:
- Instructions in retrieved content that tell the agent to ignore prior rules
- Requests to reveal or transmit secrets
- Attempts to change tool behavior or bypass approval
- Unusual urgency or instructions to conceal the action

Heuristics are imperfect. They may produce false positives and false negatives. Record the signal and confidence/reason, but do not claim comprehensive detection.

## Sensitive data
For the demo, support configurable exact canary secrets such as `DEMO_SECRET`, plus basic patterns such as email addresses and API-key-like strings where appropriate. Use synthetic data only.

## Destination classification
At minimum:
- `APPROVED`
- `UNAPPROVED`
- `INTERNAL`
- `UNKNOWN`

Normalize domains carefully. Do not treat substring matches as safe; `trusted.example.attacker.test` must not match `trusted.example`.

## Output
Return a decision, policy ID, reason codes, destination class, detected data labels, risk signals, and a redacted payload or payload fingerprint as appropriate.
