"""Verify local SQLite audit event hash chain."""

import sqlite3
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.services.audit_integrity import verify_chain


def main() -> None:
    database = Path("data/agentshield.db")
    if not database.is_file():
        raise SystemExit(f"Audit database not found: {database}")

    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    rows = [
        dict(row)
        for row in connection.execute(
            "SELECT * FROM audit_events WHERE sequence IS NOT NULL ORDER BY sequence"
        )
    ]
    connection.close()

    if not rows:
        raise SystemExit("No integrity-enabled audit events found.")

    valid, error = verify_chain(rows)
    if not valid:
        raise SystemExit(f"Audit chain invalid: {error}")
    print(f"Audit chain valid: {len(rows)} events")


if __name__ == "__main__":
    main()
