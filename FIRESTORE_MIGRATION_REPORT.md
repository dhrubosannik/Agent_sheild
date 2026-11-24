# Firestore Migration Report

## Current State

SQLite remains the local default. Firestore repositories and migration export tooling are present, but no Firebase project credentials or live Firestore emulator migration was performed in this environment.

## Migration Export

Run:

```bash
.venv/bin/python scripts/migrate_sqlite_to_firestore.py \
  --database data/agentshield.db \
  --output migration_export
```

The script backs up SQLite and exports audit_events.json and approvals.json.

Verified export in this environment:

- Audit events: 1258
- Approvals: 132
- Backup: `/tmp/agentshield-phase13-export/agentshield.db.backup`

No live Firestore upload was performed.

## Verification Required

- Compare audit count
- Compare approval count
- Compare event IDs and timestamps
- Compare decision and approval-state distributions
- Verify no raw payload or secret fields migrated
- Verify idempotent reruns do not duplicate documents
