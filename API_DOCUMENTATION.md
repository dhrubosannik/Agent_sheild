# API Contract

All endpoints are under `/api/v1` except `/health`.

## Evaluate request
`POST /api/v1/evaluate`

```json
{
  "tool_name": "send_email",
  "arguments": {
    "to": "outside@example.net",
    "subject": "Vendor update",
    "body": "Please see details. DEMO_SECRET"
  },
  "context": {
    "source": "demo_agent",
    "untrusted_sources": ["sample_vendor_document.txt"]
  }
}
```

## Evaluate response
```json
{
  "event_id": "evt_example",
  "decision": "BLOCK",
  "policy_id": "block-secret-to-unapproved",
  "reason_codes": ["PROTECTED_DATA", "UNAPPROVED_DESTINATION"],
  "destination_class": "UNAPPROVED",
  "data_labels": ["PROTECTED"],
  "risk_signals": [],
  "payload_fingerprint": "sha256:...",
  "redacted_arguments": null,
  "execution_status": "NOT_EXECUTED",
  "explanation": "Protected data cannot be sent to an unapproved destination."
}
```

The values above are illustrative. Implement consistent schemas and document any changes. The evaluate endpoint does not itself execute the tool; execution is handled by the SDK wrapper.

## Event list
`GET /api/v1/events?limit=50&decision=BLOCK`

## Approvals
- `GET /api/v1/approvals`
- `POST /api/v1/approvals/{approval_id}/decision`

Example decision body:
```json
{"decision": "REJECT", "reviewer": "demo-reviewer"}
```

## Health
`GET /health` returns service status and application version.
