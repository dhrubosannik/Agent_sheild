# SQLite to Firestore Migration

## Backup

```bash
cp data/agentshield.db data/agentshield.db.backup
```

## Export

```bash
.venv/bin/python scripts/migrate_sqlite_to_firestore.py \
  --database data/agentshield.db \
  --output migration_export
```

The export includes audit and approval JSON and a backup copy.

## Validate

- Audit event count.
- Approval count.
- Event IDs and timestamps.
- Decision distributions.
- Approval statuses.
- No raw payload or protected secret fields.

## Upload

Upload is not executed until Firebase credentials and emulator/live project verification are available. Use idempotent event and approval document IDs.

## Rollback

Retain the SQLite backup and export directory. Do not delete SQLite after migration until a Firestore count and integrity verification succeeds.
