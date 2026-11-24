"""Analyze SQLite audit events and approvals for Phase 13.1 migration investigation."""

import sqlite3
import json
from pathlib import Path

db_path = Path("data/agentshield.db")
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

total_events = cursor.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
total_approvals = cursor.execute("SELECT COUNT(*) FROM approvals").fetchone()[0]

unhashed_events = cursor.execute("SELECT COUNT(*) FROM audit_events WHERE sequence IS NULL").fetchone()[0]
hashed_events = cursor.execute("SELECT COUNT(*) FROM audit_events WHERE sequence IS NOT NULL").fetchone()[0]

first_event = cursor.execute("SELECT * FROM audit_events ORDER BY timestamp ASC LIMIT 1").fetchone()
last_unhashed = cursor.execute("SELECT * FROM audit_events WHERE sequence IS NULL ORDER BY timestamp DESC LIMIT 1").fetchone()
first_hashed = cursor.execute("SELECT * FROM audit_events WHERE sequence IS NOT NULL ORDER BY sequence ASC LIMIT 1").fetchone()
last_hashed = cursor.execute("SELECT * FROM audit_events WHERE sequence IS NOT NULL ORDER BY sequence DESC LIMIT 1").fetchone()

# Check sequence gaps
sequences = [r[0] for r in cursor.execute("SELECT sequence FROM audit_events WHERE sequence IS NOT NULL ORDER BY sequence").fetchall()]
expected_sequences = list(range(1, len(sequences) + 1))
sequence_gap = (sequences != expected_sequences)

# Check foreign key integrity
orphan_approvals = cursor.execute("""
    SELECT COUNT(*) FROM approvals a
    LEFT JOIN audit_events e ON a.event_id = e.event_id
    WHERE e.event_id IS NULL
""").fetchone()[0]

# Check decisions distribution
decisions = dict(cursor.execute("SELECT decision, COUNT(*) FROM audit_events GROUP BY decision").fetchall())
approval_statuses = dict(cursor.execute("SELECT status, COUNT(*) FROM approvals GROUP BY status").fetchall())

# Duplicate IDs check
duplicate_events = cursor.execute("SELECT event_id, COUNT(*) FROM audit_events GROUP BY event_id HAVING COUNT(*) > 1").fetchall()
duplicate_approvals = cursor.execute("SELECT approval_id, COUNT(*) FROM approvals GROUP BY approval_id HAVING COUNT(*) > 1").fetchall()

report = {
    "total_audit_events": total_events,
    "unhashed_legacy_events": unhashed_events,
    "integrity_enabled_events": hashed_events,
    "total_approvals": total_approvals,
    "orphan_approvals": orphan_approvals,
    "sequence_range": [min(sequences), max(sequences)] if sequences else None,
    "sequence_has_gaps": sequence_gap,
    "duplicate_event_ids": len(duplicate_events),
    "duplicate_approval_ids": len(duplicate_approvals),
    "decisions_breakdown": decisions,
    "approval_statuses_breakdown": approval_statuses,
    "first_event_overall": {
        "event_id": first_event["event_id"],
        "timestamp": first_event["timestamp"],
        "has_sequence": first_event["sequence"] is not None,
    } if first_event else None,
    "last_unhashed_event": {
        "event_id": last_unhashed["event_id"],
        "timestamp": last_unhashed["timestamp"],
    } if last_unhashed else None,
    "first_hashed_event": {
        "event_id": first_hashed["event_id"],
        "sequence": first_hashed["sequence"],
        "timestamp": first_hashed["timestamp"],
        "previous_hash": first_hashed["previous_event_hash"],
        "current_hash": first_hashed["current_event_hash"],
    } if first_hashed else None,
    "last_hashed_event": {
        "event_id": last_hashed["event_id"],
        "sequence": last_hashed["sequence"],
        "timestamp": last_hashed["timestamp"],
        "current_hash": last_hashed["current_event_hash"],
    } if last_hashed else None,
}

print(json.dumps(report, indent=2))
conn.close()
