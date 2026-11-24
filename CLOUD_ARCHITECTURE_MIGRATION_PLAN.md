# AgentShield Cloud Architecture Migration Plan

## Current Architecture

- React/Vite frontend served locally.
- FastAPI backend with Pydantic models.
- Shared policy engine and Python SDK.
- SQLite audit and approval persistence.
- Local demo agent and mock tools.
- Loopback startup and no Firebase authentication.

## Target Architecture

```text
Vercel React frontend
  -> Firebase Authentication ID token
  -> Render FastAPI backend
  -> Firebase Admin SDK
  -> Cloud Firestore
  -> AgentShield policy and SDK services
```

The security engine remains in Python and is not replaced by Firebase.

## Authentication Flow

1. User registers or signs in through Firebase Authentication.
2. Firebase issues an ID token and refreshes it automatically.
3. React sends `Authorization: Bearer <ID_TOKEN>`.
4. FastAPI verifies the token with Firebase Admin SDK.
5. FastAPI extracts UID and custom-claim role.
6. FastAPI enforces route permissions.
7. Firestore operations use the Admin SDK, not user-supplied UID trust.

## Firestore Collection Design

- `users/{uid}`: identity, role, status, timestamps
- `security_events/{event_id}`: metadata-only security decisions
- `audit_events/{event_id}`: chain-integrity-ready audit metadata
- `approvals/{approval_id}`: pending and reviewed approval state
- `policies/{policy_id}`: versioned policy documents
- `audit_checkpoints/{checkpoint_id}`: signed audit checkpoint state
- `system_metadata/audit_state`: latest sequence and chain hash

Raw payloads and protected values must not be stored.

## Data Migration

1. Back up `data/agentshield.db`.
2. Export audit and approval tables in timestamp/order sequence.
3. Map existing IDs and timestamps without changing semantics.
4. Validate counts and decision/status distributions.
5. Insert Firestore documents with idempotent event IDs.
6. Verify approval/event foreign consistency.
7. Preserve SQLite and keep it local-only.
8. Produce `FIRESTORE_MIGRATION_REPORT.md`.

## Render Backend

- Bind to the port supplied by Render.
- Use Uvicorn and environment variables.
- Use Firebase Admin application default credentials or injected service-account credentials.
- Use Firestore in production.
- Never silently fall back to SQLite in production.
- Keep health data non-sensitive.

## Vercel Frontend

- Build from `frontend`.
- Output `frontend/dist`.
- Configure `VITE_API_BASE_URL`.
- Configure public Firebase web variables only.
- Allow only the real Vercel origin in FastAPI CORS.
- SPA fallback through `vercel.json`.

## Security Rules

Default deny. Browser clients may read only permitted profile and dashboard information. Browser clients must not directly write audit events, policies, or approvals.

## Risks

- Credential misconfiguration
- Mixed SQLite/Firestore operation
- Missing duplicate migrations
- Approval state drift
- Firestore transaction bottlenecks
- Frontend trust in role values
- Public exposure of unauthenticated routes
- Private signing-key leakage

## Rollback

- Preserve the SQLite backup unchanged.
- Preserve migration exports and reports.
- Retain the local startup workflow.
- Test migration and rollback before public traffic changes.
- Roll back frontend/backend environment variables if Firestore activation fails.

## Public-Deployment Gate

Public deployment remains blocked until authentication, roles, Firestore authorization, audit integrity, checkpoint verification, and security tests are verified.
