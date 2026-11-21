"""SQLite database management and schema definitions for AgentShield."""

from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
import sqlite3

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
"""


class Database:
    """Manages SQLite connections and table initialization."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        if db_path is not None:
            candidate = str(db_path)
            if candidate == ":memory:":
                self._db_path = ":memory:"
                # Keep a persistent connection for in-memory databases
                self._memory_conn: sqlite3.Connection | None = sqlite3.connect(
                    ":memory:",
                    check_same_thread=False,
                )
                self._memory_conn.row_factory = sqlite3.Row
                self._init_schema(self._memory_conn)
            else:
                self._db_path = str(resolve_database_path(candidate))
                self._memory_conn = None
                self._ensure_initialized()
        else:
            self._db_path = str(resolve_database_path())
            self._memory_conn = None
            self._ensure_initialized()

    def _ensure_initialized(self) -> None:
        with self.connection() as conn:
            self._init_schema(conn)

    def _init_schema(self, conn: sqlite3.Connection) -> None:
        conn.executescript(SCHEMA_SQL)
        conn.commit()

    @contextmanager
    def connection(self) -> Generator[sqlite3.Connection, None, None]:
        if self._memory_conn is not None:
            yield self._memory_conn
            return

        conn = sqlite3.connect(self._db_path, check_same_thread=False, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        try:
            yield conn
        finally:
            conn.close()


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
