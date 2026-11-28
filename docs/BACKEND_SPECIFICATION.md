# Backend Specification

## Responsibilities
- Expose health and decision APIs through FastAPI.
- Validate incoming requests with Pydantic.
- Load and validate policy configuration.
- Call a shared policy evaluation service.
- Record redacted audit events.
- Expose read-only audit-event listing and pending-approval operations for the demo.

## Suggested endpoints
- `GET /health` — service status and version.
- `POST /api/v1/evaluate` — evaluate a proposed tool call without executing it.
- `GET /api/v1/events` — list audit events with pagination/filtering.
- `GET /api/v1/events/{event_id}` — retrieve one event.
- `GET /api/v1/approvals` — list pending approvals.
- `POST /api/v1/approvals/{approval_id}/decision` — approve or reject a pending action.

## Rules
- API routes must remain thin; business logic belongs in services.
- Return structured error responses.
- Validate all inputs and reject malformed requests.
- Never expose raw secret values in API responses or logs.
- Approval endpoints must not execute a tool by themselves unless the demo explicitly implements a safe, traceable resume mechanism. For MVP, recording approval/rejection is sufficient; explain this limitation.
