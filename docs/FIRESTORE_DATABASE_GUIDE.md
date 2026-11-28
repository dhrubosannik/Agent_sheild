# Firestore Database Guide

Collections:

- `users/{uid}`
- `security_events/{event_id}`
- `audit_events/{event_id}`
- `approvals/{approval_id}`
- `policies/{policy_id}`
- `audit_checkpoints/{checkpoint_id}`
- `system_metadata/audit_state`

The backend uses Firebase Admin SDK for protected persistence. Browser clients must use Firestore only for permitted reads and must not directly write audit, policy, or approval documents.
