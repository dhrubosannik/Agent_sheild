"""SQLite database management and schema definitions for AgentShield."""

from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
import sqlite3
import threading

from ..core.config import resolve_database_path

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS audit_events (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    decision TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    reason_codes TEXT NOT NULL,
    destination_class TEXT NOT NULL,
    data_labels TEXT NOT NULL,
    risk_signals TEXT NOT NULL,
    payload_fingerprint TEXT,
    execution_status TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_decision ON audit_events(decision);
CREATE INDEX IF NOT EXISTS idx_audit_events_tool_name ON audit_events(tool_name);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    requested_action TEXT NOT NULL,
    destination_class TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    reviewer TEXT,
    reviewed_at TEXT,
    FOREIGN KEY(event_id) REFERENCES audit_events(event_id)
);

CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);
CREATE INDEX IF NOT EXISTS idx_approvals_event_id ON approvals(event_id);

CREATE TABLE IF NOT EXISTS audit_chain_migrations (
    migration_id TEXT PRIMARY KEY,
    migrated_at TEXT NOT NULL,
    legacy_event_count INTEGER NOT NULL,
    legacy_unsequenced_count INTEGER NOT NULL,
    legacy_max_sequence INTEGER,
    legacy_head_hash TEXT,
    legacy_chain_consistent INTEGER NOT NULL,
    legacy_chain_error TEXT,
    note TEXT NOT NULL
);
"""

# v2 schema additions. Partial unique index: legacy rows (chain_version NULL)
# keep whatever sequence values they had; v2 sequences are unique.
V2_SCHEMA_SQL = """
CREATE UNIQUE INDEX IF NOT EXISTS ux_audit_events_v2_sequence
    ON audit_events(sequence) WHERE chain_version = 2;
CREATE INDEX IF NOT EXISTS idx_audit_events_related ON audit_events(related_event_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_ts_id ON audit_events(timestamp DESC, event_id DESC);

CREATE TABLE IF NOT EXISTS audit_chain_state (
    chain_version INTEGER PRIMARY KEY,
    sequence INTEGER NOT NULL,
    current_event_hash TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS audit_events_append_only_update
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_events_append_only_delete
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_chain_migrations_append_only_update
BEFORE UPDATE ON audit_chain_migrations
BEGIN
    SELECT RAISE(ABORT, 'audit_chain_migrations is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_chain_migrations_append_only_delete
BEFORE DELETE ON audit_chain_migrations
BEGIN
    SELECT RAISE(ABORT, 'audit_chain_migrations is append-only');
END;
"""

MIGRATION_ID = "chain-v2"


class Database:
    """Manages SQLite connections and table initialization."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        # Serializes appends within this process; BEGIN IMMEDIATE serializes
        # across processes sharing the same database file.
        self._write_lock = threading.RLock()
        if db_path is not None and str(db_path) == ":memory:":
            self._db_path = ":memory:"
            self._memory_conn: sqlite3.Connection | None = sqlite3.connect(
                ":memory:",
                check_same_thread=False,
                isolation_level=None,
            )
            self._memory_conn.row_factory = sqlite3.Row
            self._ensure_initialized()
        else:
            self._db_path = str(resolve_database_path(str(db_path) if db_path is not None else None))
            self._memory_conn = None
            self._ensure_initialized()

    def _ensure_initialized(self) -> None:
        with self.write_transaction() as conn:
            self._init_schema(conn)

    def _init_schema(self, conn: sqlite3.Connection) -> None:
        _exec_statements(conn, SCHEMA_SQL)
        audit_columns = {row[1] for row in conn.execute("PRAGMA table_info(audit_events)")}
        for name, definition in {
            "sequence": "INTEGER",
            "previous_event_hash": "TEXT",
            "current_event_hash": "TEXT",
            "actor_uid": "TEXT",
            "chain_version": "INTEGER",
            "event_type": "TEXT",
            "related_event_id": "TEXT",
        }.items():
            if name not in audit_columns:
                conn.execute(f"ALTER TABLE audit_events ADD COLUMN {name} {definition}")

        self._record_migration(conn)
        _exec_statements(conn, V2_SCHEMA_SQL)

    def _record_migration(self, conn: sqlite3.Connection) -> None:
        """Records, once, the state of legacy records at the moment the v2
        append-only chain is introduced. Legacy rows are never modified."""
        existing = conn.execute(
            "SELECT 1 FROM audit_chain_migrations WHERE migration_id = ?", (MIGRATION_ID,)
        ).fetchone()
        if existing is not None:
            return

        from ..services.audit_integrity import verify_chain

        rows = [
            dict(row)
            for row in conn.execute(
                "SELECT * FROM audit_events WHERE chain_version IS NULL"
            )
        ]
        sequenced = [row for row in rows if row.get("sequence") is not None]
        consistent, error = verify_chain(sequenced, version=1) if sequenced else (True, None)
        head = max(sequenced, key=lambda row: int(row["sequence"]), default=None)
        conn.execute(
            """
            INSERT INTO audit_chain_migrations (
                migration_id, migrated_at, legacy_event_count, legacy_unsequenced_count,
                legacy_max_sequence, legacy_head_hash, legacy_chain_consistent,
                legacy_chain_error, note
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                MIGRATION_ID,
                datetime.now(UTC).isoformat(),
                len(rows),
                len(rows) - len(sequenced),
                int(head["sequence"]) if head else None,
                head["current_event_hash"] if head else None,
                1 if consistent else 0,
                error,
                "Legacy (v1) records retained unchanged. Their hashes were produced "
                "without append-only or unique-sequence enforcement and do not prove "
                "historical integrity. Verified records start at chain_version 2.",
            ),
        )

    @contextmanager
    def connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Connection for reads and non-audit writes (autocommit)."""
        if self._memory_conn is not None:
            with self._write_lock:
                yield self._memory_conn
            return

        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def write_transaction(self) -> Generator[sqlite3.Connection, None, None]:
        """Serialized write transaction (BEGIN IMMEDIATE) committed on success."""
        with self._write_lock:
            if self._memory_conn is not None:
                conn = self._memory_conn
                close = False
            else:
                conn = self._connect()
                close = True
            try:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    yield conn
                except BaseException:
                    conn.execute("ROLLBACK")
                    raise
                else:
                    conn.execute("COMMIT")
            finally:
                if close:
                    conn.close()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self._db_path,
            check_same_thread=False,
            timeout=30.0,
            isolation_level=None,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA busy_timeout=30000;")
        return conn


def _exec_statements(conn: sqlite3.Connection, script: str) -> None:
    """Executes a multi-statement script inside an open transaction
    (``executescript`` would implicitly COMMIT first)."""
    buffer = ""
    for line in script.splitlines(keepends=True):
        buffer += line
        if sqlite3.complete_statement(buffer):
            statement = buffer.strip()
            if statement:
                conn.execute(statement)
            buffer = ""


_global_database: Database | None = None


def get_database(db_path: str | Path | None = None) -> Database:
    """Returns the database singleton or creates a database instance for custom paths."""
    global _global_database
    if db_path is not None:
        return Database(db_path)
    if _global_database is None:
        _global_database = Database()
    return _global_database


def reset_database_singleton() -> None:
    """Resets the database singleton (useful during tests)."""
    global _global_database
    _global_database = None
