"""Safe, idempotent SQLite to Firestore migration with provenance tracking and verification.

Preserves legacy records, distinguishes unhashed vs integrity-protected events,
and validates migration counts, duplicates, ordering, and hash integrity.
"""

import argparse
from datetime import datetime, UTC
import json
from pathlib import Path
import shutil
import sqlite3
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.services.audit_integrity import verify_chain


def run_migration(
    sqlite_path: Path,
    firestore_client=None,
    audit_collection: str = "migration_test_audit_events",
    approval_collection: str = "migration_test_approvals",
    metadata_collection: str = "system_metadata",
    dry_run: bool = False,
    backup_dir: Path | None = None,
) -> dict:
    if not sqlite_path.is_file():
        raise FileNotFoundError(f"SQLite database not found: {sqlite_path}")

    # Step 1: Backup SQLite database (never modify or overwrite)
    backup_path = None
    if backup_dir:
        backup_dir.mkdir(parents=True, exist_ok=True)
        ts_str = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        backup_path = backup_dir / f"{sqlite_path.stem}_{ts_str}.db.backup"
        shutil.copy2(sqlite_path, backup_path)

    # Step 2: Read source SQLite records
    conn = sqlite3.connect(sqlite_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    source_audit_rows = [dict(r) for r in c.execute("SELECT * FROM audit_events ORDER BY timestamp ASC")]
    source_approval_rows = [dict(r) for r in c.execute("SELECT * FROM approvals ORDER BY created_at ASC")]
    conn.close()

    total_source_audits = len(source_audit_rows)
    total_source_approvals = len(source_approval_rows)

    # Step 3: Classify audit records into legacy vs integrity-enabled
    legacy_events = []
    integrity_events = []

    for row in source_audit_rows:
        # Parse JSON fields safely
        for key in ("reason_codes", "data_labels", "risk_signals"):
            val = row.get(key)
            if isinstance(val, str):
                try:
                    row[key] = json.loads(val)
                except Exception:
                    row[key] = [val]

        if row.get("sequence") is None or row.get("current_event_hash") is None:
            # Legacy unhashed record
            row["migration_provenance"] = "legacy_sqlite_unhashed"
            row["integrity_verified_prior_to_migration"] = False
            legacy_events.append(row)
        else:
            # Cryptographically chained record
            row["migration_provenance"] = "sqlite_hash_chain_v1"
            row["integrity_verified_prior_to_migration"] = True
            integrity_events.append(row)

    CANONICAL_KEYS = {
        "event_id", "timestamp", "tool_name", "decision", "policy_id",
        "reason_codes", "destination_class", "data_labels", "risk_signals",
        "payload_fingerprint", "execution_status", "sequence",
        "previous_event_hash", "current_event_hash", "actor_uid",
    }
    # Verify integrity chain of integrity_events prior to upload using canonical fields
    chain_valid, chain_err = verify_chain([
        {k: doc[k] for k in CANONICAL_KEYS if k in doc}
        for doc in integrity_events
    ])
    if not chain_valid:
        raise ValueError(f"Source integrity chain failed verification: {chain_err}")

    migrated_audits = []
    migrated_approvals = []

    # Step 4: Perform upload to Firestore (or simulate in dry-run)
    if firestore_client is not None and not dry_run:
        batch = firestore_client.batch()
        batch_count = 0

        # Upload audit events
        for doc in legacy_events + integrity_events:
            doc_ref = firestore_client.collection(audit_collection).document(doc["event_id"])
            batch.set(doc_ref, doc)
            batch_count += 1
            if batch_count >= 400:
                batch.commit()
                batch = firestore_client.batch()
                batch_count = 0

        # Upload approvals
        for doc in source_approval_rows:
            doc_ref = firestore_client.collection(approval_collection).document(doc["approval_id"])
            batch.set(doc_ref, doc)
            batch_count += 1
            if batch_count >= 400:
                batch.commit()
                batch = firestore_client.batch()
                batch_count = 0

        if batch_count > 0:
            batch.commit()

        # Record migration metadata
        migration_meta = {
            "migration_timestamp": datetime.now(UTC).isoformat(),
            "source_sqlite_path": str(sqlite_path),
            "backup_path": str(backup_path) if backup_path else None,
            "total_audit_events": total_source_audits,
            "legacy_unhashed_count": len(legacy_events),
            "integrity_enabled_count": len(integrity_events),
            "total_approvals": total_source_approvals,
            "integrity_chain_valid": chain_valid,
            "first_integrity_sequence": integrity_events[0]["sequence"] if integrity_events else None,
            "last_integrity_sequence": integrity_events[-1]["sequence"] if integrity_events else None,
            "last_integrity_hash": integrity_events[-1]["current_event_hash"] if integrity_events else None,
        }
        firestore_client.collection(metadata_collection).document("migration_manifest").set(migration_meta)

        # Step 5: Read back from Firestore to verify migration fidelity
        dest_audit_docs = list(firestore_client.collection(audit_collection).stream())
        dest_approval_docs = list(firestore_client.collection(approval_collection).stream())

        migrated_audits = [d.to_dict() for d in dest_audit_docs]
        migrated_approvals = [d.to_dict() for d in dest_approval_docs]
    else:
        # In dry run mode, simulation uses in-memory records
        migrated_audits = legacy_events + integrity_events
        migrated_approvals = source_approval_rows

    # Step 6: Verification checks
    source_event_ids = {r["event_id"] for r in source_audit_rows}
    migrated_event_ids = {r["event_id"] for r in migrated_audits}
    missing_events = list(source_event_ids - migrated_event_ids)
    duplicate_events = len(migrated_audits) - len(migrated_event_ids)

    source_approval_ids = {r["approval_id"] for r in source_approval_rows}
    migrated_approval_ids = {r["approval_id"] for r in migrated_approvals}
    missing_approvals = list(source_approval_ids - migrated_approval_ids)
    duplicate_approvals = len(migrated_approvals) - len(migrated_approval_ids)

    # Re-verify integrity chain on read-back documents using canonical fields
    migrated_chained = [
        {k: r[k] for k in CANONICAL_KEYS if k in r}
        for r in migrated_audits
        if r.get("sequence") is not None
    ]
    migrated_chain_valid, migrated_chain_err = verify_chain(migrated_chained)

    verification_report = {
        "source_sqlite_path": str(sqlite_path),
        "backup_path": str(backup_path) if backup_path else None,
        "total_source_audits": total_source_audits,
        "total_migrated_audits": len(migrated_audits),
        "legacy_unhashed_audits": len(legacy_events),
        "integrity_protected_audits": len(integrity_events),
        "duplicate_audits": duplicate_events,
        "missing_audits_count": len(missing_events),
        "total_source_approvals": total_source_approvals,
        "total_migrated_approvals": len(migrated_approvals),
        "duplicate_approvals": duplicate_approvals,
        "missing_approvals_count": len(missing_approvals),
        "source_chain_valid": chain_valid,
        "migrated_chain_valid": migrated_chain_valid,
        "migrated_chain_error": migrated_chain_err,
        "decision_distribution_source": {
            d: sum(1 for r in source_audit_rows if r["decision"] == d)
            for d in ("ALLOW", "BLOCK", "REDACT", "REQUIRE_APPROVAL")
        },
        "decision_distribution_migrated": {
            d: sum(1 for r in migrated_audits if r["decision"] == d)
            for d in ("ALLOW", "BLOCK", "REDACT", "REQUIRE_APPROVAL")
        },
        "status": "PASS" if (
            len(migrated_audits) == total_source_audits
            and len(migrated_approvals) == total_source_approvals
            and duplicate_events == 0
            and duplicate_approvals == 0
            and migrated_chain_valid
        ) else "FAIL",
    }
    return verification_report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", default="data/agentshield.db")
    parser.add_argument("--backup-dir", default="data/backups")
    parser.add_argument("--audit-collection", default="migration_test_audit_events")
    parser.add_argument("--approval-collection", default="migration_test_approvals")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    client = None
    if not args.dry_run:
        import os
        os.environ.setdefault("DATABASE_MODE", "firestore")
        os.environ.setdefault("FIREBASE_PROJECT_ID", "demo-agentshield")
        from backend.app.core.config import get_settings
        get_settings.cache_clear()
        try:
            from backend.app.core.firestore import get_firestore_client
            client = get_firestore_client()
        except Exception as e:
            print(f"Firestore client unavailable ({e}), defaulting to dry-run analysis.")
            args.dry_run = True

    report = run_migration(
        sqlite_path=Path(args.database),
        firestore_client=client,
        audit_collection=args.audit_collection,
        approval_collection=args.approval_collection,
        dry_run=args.dry_run,
        backup_dir=Path(args.backup_dir),
    )
    print(json.dumps(report, indent=2))
    with open("scripts/migration_verification_results.json", "w") as f:
        json.dump(report, f, indent=2)


if __name__ == "__main__":
    main()
