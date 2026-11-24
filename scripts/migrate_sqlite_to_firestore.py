"""Exports existing SQLite audit and approval data for idempotent Firestore migration."""

import argparse
import json
from pathlib import Path
import shutil
import sqlite3
from datetime import UTC, datetime


def export_sqlite(database_path: Path, output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    backup_path = output_dir / f"{database_path.name}.backup"
    shutil.copy2(database_path, backup_path)

    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row

    audit_rows = [dict(row) for row in connection.execute("SELECT * FROM audit_events ORDER BY timestamp")]
    approval_rows = [dict(row) for row in connection.execute("SELECT * FROM approvals ORDER BY created_at")]
    connection.close()

    generated_at = datetime.now(UTC).isoformat()
    (output_dir / "audit_events.json").write_text(
        json.dumps({"generated_at": generated_at, "items": audit_rows}, indent=2),
        encoding="utf-8",
    )
    (output_dir / "approvals.json").write_text(
        json.dumps({"generated_at": generated_at, "items": approval_rows}, indent=2),
        encoding="utf-8",
    )
    return {
        "audit_count": len(audit_rows),
        "approval_count": len(approval_rows),
        "backup": str(backup_path),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", default="data/agentshield.db")
    parser.add_argument("--output", default="migration_export")
    args = parser.parse_args()

    database_path = Path(args.database)
    if not database_path.is_file():
        raise SystemExit(f"SQLite database not found: {database_path}")

    report = export_sqlite(database_path, Path(args.output))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
