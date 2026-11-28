# Audit Logging Specification

## Purpose
Provide a safe, explainable record of each evaluated tool call.

## Minimum fields
- `event_id`
- `timestamp` (UTC ISO-8601)
- `tool_name`
- `decision`
- `policy_id`
- `reason_codes`
- `destination_class`
- `data_labels`
- `risk_signals` (names/reasons, not untrusted raw content)
- `payload_fingerprint` (e.g. SHA-256 of a canonicalized payload, with documented caveats)
- `execution_status` (`NOT_EXECUTED`, `EXECUTED`, `PENDING_APPROVAL`, `REDACTED_AND_EXECUTED`, `FAILED`)

## Privacy requirements
- Never store raw secret values.
- Never store full sensitive payloads by default.
- Redact email addresses or other personal data in event summaries where practical.
- Do not include untrusted document text in audit messages.
- Avoid logging credentials, tokens, authorization headers, or environment variables.

## Storage
Use JSONL or SQLite for the MVP. Make writes robust and test concurrent or repeated writes to the extent practical. Document retention and local-demo limitations.
