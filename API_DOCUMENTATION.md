# AgentShield API Documentation

The AgentShield backend exposes REST endpoints for evaluating proposed AI-agent tool calls, retrieving privacy-safe audit trails, and managing human approvals.

All resource endpoints are versioned under `/api/v1` except `/health`.

---

## 1. Health Check

### `GET /health`
Returns application name, status, and running version.

#### Response `200 OK`
```json
{
  "name": "AgentShield",
  "status": "healthy",
  "version": "0.1.0"
}
```

---

## 2. Policy Evaluation

### `POST /api/v1/evaluate`
Inspects a proposed tool call and its arguments against deterministic security policies.

> **CRITICAL:** This endpoint **strictly evaluates** proposed arguments against policies and generates a persistent audit event. It **does NOT execute** the underlying tool. Tool execution is handled client-side by the AgentShield SDK wrapper.

#### Request Headers
`Content-Type: application/json`

#### Request Body Schema
| Field | Type | Required | Description |
|---|---|---|---|
| `tool_name` | string | Yes | Non-empty name of the tool to be invoked (e.g. `send_email`). |
| `arguments` | object | Yes | JSON-compatible dictionary of proposed tool arguments. |
| `context` | object | No | Optional dictionary providing execution context (e.g. untrusted document source). |
| `request_id` | UUID | No | Client-supplied request UUID (auto-generated if omitted). |

#### Example Request
```json
{
  "tool_name": "send_email",
  "arguments": {
    "to": "outside@example.net",
    "subject": "Vendor update",
    "body": "Canary token: DEMO_SECRET"
  },
  "context": {
    "source": "demo_agent",
    "untrusted_sources": ["sample_vendor_document.txt"]
  }
}
```

#### Response `200 OK` Schema
```json
{
  "event_id": "evt-7a8b9c0d1e2f",
  "decision": "BLOCK",
  "policy_id": "block-secret-to-unapproved",
  "reason_codes": [
    "POLICY_BLOCK_RULE",
    "PROTECTED_DATA",
    "UNAPPROVED_DESTINATION"
  ],
  "destination_class": "UNAPPROVED",
  "data_labels": [
    "PROTECTED"
  ],
  "risk_signals": [],
  "payload_fingerprint": "sha256:d82e7ba1562947a1...",
  "redacted_arguments": null,
  "execution_status": "NOT_EXECUTED",
  "explanation": "Action blocked by policy rule 'block-secret-to-unapproved': Block protected data sent to unapproved destinations."
}
```

#### Error Responses
- `422 Unprocessable Entity`: Request body failed validation (e.g., missing tool_name or invalid JSON structure).

---

## 3. Audit Events

### `GET /api/v1/events`
Lists paginated audit event records.

#### Query Parameters
| Parameter | Type | Default | Description |
|---|---|---|---|
| `limit` | integer | `50` | Maximum number of records to return (1 to 100). |
| `offset` | integer | `0` | Number of records to skip. |
| `decision` | string | `null` | Filter by decision (`ALLOW`, `REDACT`, `REQUIRE_APPROVAL`, `BLOCK`). |
| `tool_name` | string | `null` | Filter by tool name. |

#### Example Request
`GET /api/v1/events?limit=25&offset=0&decision=BLOCK`

#### Response `200 OK`
```json
{
  "items": [
    {
      "event_id": "evt-7a8b9c0d1e2f",
      "timestamp": "2026-11-21T18:14:00.123456+00:00",
      "tool_name": "send_email",
      "decision": "BLOCK",
      "policy_id": "block-secret-to-unapproved",
      "reason_codes": ["POLICY_BLOCK_RULE", "PROTECTED_DATA", "UNAPPROVED_DESTINATION"],
      "destination_class": "UNAPPROVED",
      "data_labels": ["PROTECTED"],
      "risk_signals": [],
      "payload_fingerprint": "sha256:d82e7ba...",
      "execution_status": "NOT_EXECUTED"
    }
  ],
  "total": 1,
  "limit": 25,
  "offset": 0
}
```

---

### `GET /api/v1/events/{event_id}`
Retrieves a single audit event record by its unique ID.

#### Response `200 OK`
Returns the `AuditEvent` object matching `{event_id}`.

#### Error Responses
- `404 Not Found`: Event with ID `{event_id}` does not exist.

---

## 4. Human Approval Management

### `GET /api/v1/approvals`
Lists approval records created when actions require human approval.

#### Query Parameters
| Parameter | Type | Default | Description |
|---|---|---|---|
| `status` | string | `null` | Filter by status (`PENDING`, `APPROVED`, `REJECTED`). |
| `limit` | integer | `50` | Maximum number of records to return (1 to 100). |
| `offset` | integer | `0` | Number of records to skip. |

#### Example Request
`GET /api/v1/approvals?status=PENDING`

#### Response `200 OK`
```json
{
  "items": [
    {
      "approval_id": "apr-evt-7a8b9c0d1e2f",
      "event_id": "evt-7a8b9c0d1e2f",
      "tool_name": "export_file",
      "requested_action": "Execute tool 'export_file'",
      "destination_class": "UNAPPROVED",
      "status": "PENDING",
      "created_at": "2026-11-21T18:14:00.123456+00:00",
      "reviewer": null,
      "reviewed_at": null
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0
}
```

---

### `POST /api/v1/approvals/{approval_id}/decision`
Records a human decision (`APPROVED` or `REJECTED`) for a pending approval request.

> **NOTE:** Reviewing an approval strictly updates the approval record in the audit database. It does not automatically execute the underlying tool call.

#### Request Body Schema
| Field | Type | Required | Description |
|---|---|---|---|
| `decision` | string | Yes | Must be `"APPROVED"` or `"REJECTED"`. |
| `reviewer` | string | Yes | Identity/username of the reviewer. |

#### Example Request
```json
{
  "decision": "APPROVED",
  "reviewer": "security_admin"
}
```

#### Response `200 OK`
```json
{
  "approval_id": "apr-evt-7a8b9c0d1e2f",
  "event_id": "evt-7a8b9c0d1e2f",
  "tool_name": "export_file",
  "requested_action": "Execute tool 'export_file'",
  "destination_class": "UNAPPROVED",
  "status": "APPROVED",
  "created_at": "2026-11-21T18:14:00.123456+00:00",
  "reviewer": "security_admin",
  "reviewed_at": "2026-11-21T18:15:30.987654+00:00"
}
```

#### Error Responses
- `404 Not Found`: Approval with `{approval_id}` does not exist.
- `409 Conflict`: Approval has already been reviewed (only `PENDING` approvals can be decided).

---

## 5. Local Development Commands

### Run Backend Server
```bash
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Run Full Test Suite
```bash
pytest backend/tests sdk/tests
```

### Interactive API Documentation (Swagger UI)
Once the server is running, navigate to:
`http://127.0.0.1:8000/docs`
