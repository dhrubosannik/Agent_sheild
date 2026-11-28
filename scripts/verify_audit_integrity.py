"""Verify the local SQLite audit log (read-only; never migrates or writes).

Reports two segments separately:
* legacy (v1) records: internal consistency only; NOT proof of historical
  integrity (they were written without append-only/unique-sequence controls);
* verified (v2) records: append-only, unique sequence, checked against the
  recorded chain head.

Exit code 1 if the verified chain is invalid.
"""

import argparse
import json
import sqlite3
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.services.audit_integrity import CHAIN_VERSION, verify_audit_log


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", default=str(PROJECT_ROOT / "data" / "agentshield.db"))
    args = parser.parse_args()
    database = Path(args.database)
    if not database.is_file():
        raise SystemExit(f"Audit database not found: {database}")

    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    rows = [dict(row) for row in connection.execute("SELECT * FROM audit_events")]
    tables = {r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    head = None
    migration = None
    if "audit_chain_state" in tables:
        row = connection.execute(
            "SELECT sequence, current_event_hash FROM audit_chain_state WHERE chain_version = ?", (CHAIN_VERSION,)
        ).fetchone()
        head = dict(row) if row else None
    if "audit_chain_migrations" in tables:
        row = connection.execute("SELECT * FROM audit_chain_migrations").fetchone()
        migration = dict(row) if row else None
    connection.close()

    report = verify_audit_log(rows, v2_head=head)
    report["migration"] = migration or "not yet migrated (database has not been opened by the v2 backend)"
    print(json.dumps(report, indent=2))
    if report["verified"]["count"] and not report["verified"]["valid"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
