"""Append-only, hash-chained audit log tests (Phase 13.2, Priority 3)."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
import json
from pathlib import Path
import sqlite3

import pytest

from backend.app.models.audit_event import AuditEvent
from backend.app.models.enums import DestinationClass, ExecutionStatus, SecurityDecision
from backend.app.services.audit_integrity import (
    GENESIS_V1,
    GENESIS_V2,
    compute_event_hash,
    verify_audit_log,
    verify_chain,
)
from backend.app.services.audit_logger import AuditLogger
from backend.app.storage.audit_repository import AuditChainError, AuditRepository
from backend.app.storage.database import Database


def _event(index: int, **overrides) -> AuditEvent:
    data = dict(
        event_id=f"evt-{index:05d}",
        timestamp=datetime.now(UTC),
        tool_name="send_email",
        decision=SecurityDecision.ALLOW,
        policy_id="default-allow-safe",
        reason_codes=["SAFE_ACTION"],
        destination_class=DestinationClass.APPROVED,
        data_labels=[],
        risk_signals=[],
        payload_fingerprint=f"sha256:{index:064d}",
        execution_status=ExecutionStatus.EXECUTED,
    )
    data.update(overrides)
    return AuditEvent(**data)


@pytest.fixture
def db(tmp_path: Path) -> Database:
    return Database(tmp_path / "audit.db")


def _rows(db: Database) -> list[dict]:
    with db.connection() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM audit_events")]


def _raw(db: Database) -> sqlite3.Connection:
    conn = sqlite3.connect(db._db_path, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn


def _report(db: Database) -> dict:
    repo = AuditRepository(db)
    return verify_audit_log(repo.export_chain_records(), v2_head=repo.chain_head())


def test_appends_form_a_valid_v2_chain(db: Database) -> None:
    repo = AuditRepository(db)
    created = [repo.create(_event(i)) for i in range(5)]
    assert [e.sequence for e in created] == [1, 2, 3, 4, 5]
    assert created[0].previous_event_hash == GENESIS_V2
    assert all(created[i].previous_event_hash == created[i - 1].current_event_hash for i in range(1, 5))
    assert _report(db)["verified"] == {"count": 5, "valid": True, "error": None}


def test_caller_cannot_choose_sequence_or_previous_hash(db: Database) -> None:
    repo = AuditRepository(db)
    repo.create(_event(1))
    forged = repo.create(_event(2, sequence=99, previous_event_hash="forged", current_event_hash="forged"))
    assert forged.sequence == 2
    assert forged.previous_event_hash != "forged"
    assert _report(db)["verified"]["valid"] is True


def test_update_and_delete_are_rejected_by_the_database(db: Database) -> None:
    AuditRepository(db).create(_event(1))
    conn = _raw(db)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("UPDATE audit_events SET decision = 'BLOCK'")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("DELETE FROM audit_events")
    conn.close()


def test_duplicate_v2_sequence_is_rejected_by_unique_index(db: Database) -> None:
    AuditRepository(db).create(_event(1))
    row = _rows(db)[0]
    row["event_id"] = "evt-duplicate"
    conn = _raw(db)
    columns = ",".join(row)
    with pytest.raises(sqlite3.IntegrityError, match="UNIQUE"):
        conn.execute(f"INSERT INTO audit_events ({columns}) VALUES ({','.join('?' for _ in row)})", list(row.values()))
    conn.close()


def test_execution_status_change_is_appended_not_updated(db: Database) -> None:
    logger = AuditLogger(db=db)
    repo = logger.audit_repo
    original = repo.create(_event(1, execution_status=ExecutionStatus.NOT_EXECUTED))
    before = _rows(db)

    assert logger.update_execution_status(original.event_id, ExecutionStatus.EXECUTED) is True

    after = _rows(db)
    assert len(after) == len(before) + 1
    assert [r for r in after if r["event_id"] == original.event_id] == before
    fetched = repo.get_by_id(original.event_id)
    assert fetched.execution_status == ExecutionStatus.NOT_EXECUTED
    assert fetched.effective_execution_status == ExecutionStatus.EXECUTED
    items, total = repo.list_events()
    assert total == 1 and items[0].effective_execution_status == ExecutionStatus.EXECUTED
    assert _report(db)["verified"]["valid"] is True


def _tamper(db: Database, sql: str, params: tuple = ()) -> None:
    """Simulates an attacker with direct file access (drops the triggers)."""
    conn = _raw(db)
    conn.execute("DROP TRIGGER audit_events_append_only_update")
    conn.execute("DROP TRIGGER audit_events_append_only_delete")
    conn.execute(sql, params)
    conn.close()


def test_tampered_field_is_detected(db: Database) -> None:
    repo = AuditRepository(db)
    for i in range(4):
        repo.create(_event(i))
    _tamper(db, "UPDATE audit_events SET decision = 'BLOCK' WHERE sequence = 2 AND chain_version = 2")
    result = _report(db)["verified"]
    assert result["valid"] is False
    assert "Modified event at sequence 2" in result["error"]


def test_tampered_hash_link_is_detected(db: Database) -> None:
    repo = AuditRepository(db)
    for i in range(3):
        repo.create(_event(i))
    _tamper(db, "UPDATE audit_events SET previous_event_hash = 'x' WHERE sequence = 3 AND chain_version = 2")
    assert "Previous hash mismatch" in _report(db)["verified"]["error"]


def test_deleted_middle_record_is_detected(db: Database) -> None:
    repo = AuditRepository(db)
    for i in range(5):
        repo.create(_event(i))
    _tamper(db, "DELETE FROM audit_events WHERE sequence = 3 AND chain_version = 2")
    assert "Missing or reordered sequence" in _report(db)["verified"]["error"]


def test_deleted_newest_record_is_detected_by_chain_head(db: Database) -> None:
    repo = AuditRepository(db)
    for i in range(5):
        repo.create(_event(i))
    _tamper(db, "DELETE FROM audit_events WHERE sequence = 5 AND chain_version = 2")
    assert "Chain head mismatch" in _report(db)["verified"]["error"]
    # Appending on top of an inconsistent chain is refused.
    with pytest.raises(AuditChainError):
        repo.create(_event(99))


def test_duplicate_and_missing_sequences_detected_by_verifier() -> None:
    events, previous = [], GENESIS_V1
    for seq in (1, 2, 2):
        payload = {"event_id": f"e{len(events)}", "sequence": seq}
        current = compute_event_hash(payload, previous)
        events.append({**payload, "previous_event_hash": previous, "current_event_hash": current})
        previous = current
    assert verify_chain(events) == (False, "Duplicate sequence 2")

    gap = [e for e in events[:2]]
    gap[1] = {**gap[1], "sequence": 3}
    valid, error = verify_chain(gap)
    assert valid is False and "Missing or reordered sequence at 3" in error


def test_concurrent_appends_produce_one_valid_chain(db: Database) -> None:
    repo = AuditRepository(db)
    with ThreadPoolExecutor(max_workers=16) as pool:
        created = list(pool.map(lambda i: repo.create(_event(i)), range(200)))
    sequences = sorted(e.sequence for e in created)
    assert sequences == list(range(1, 201))
    report = _report(db)
    assert report["verified"] == {"count": 200, "valid": True, "error": None}


def test_concurrent_appends_from_independent_connections(tmp_path: Path) -> None:
    """Separate Database objects do not share the in-process lock (like separate
    processes or workers); BEGIN IMMEDIATE must still serialize them."""
    path = tmp_path / "shared.db"
    databases = [Database(path) for _ in range(4)]
    repos = [AuditRepository(d) for d in databases]

    def write(i: int) -> int:
        return repos[i % 4].create(_event(i)).sequence

    with ThreadPoolExecutor(max_workers=8) as pool:
        sequences = list(pool.map(write, range(120)))
    assert sorted(sequences) == list(range(1, 121))
    assert _report(databases[0])["verified"]["valid"] is True


def test_concurrent_status_changes_and_decisions_stay_consistent(db: Database) -> None:
    logger = AuditLogger(db=db)
    base = [logger.audit_repo.create(_event(i, execution_status=ExecutionStatus.NOT_EXECUTED)) for i in range(20)]

    def mixed(i: int) -> None:
        if i % 2:
            logger.update_execution_status(base[i % 20].event_id, ExecutionStatus.EXECUTED)
        else:
            logger.audit_repo.create(_event(1000 + i))

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(mixed, range(60)))
    assert _report(db)["verified"]["valid"] is True


# --------------------------------------------------------------------------- #
# Legacy migration
# --------------------------------------------------------------------------- #

LEGACY_SCHEMA = """
CREATE TABLE audit_events (
    event_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, tool_name TEXT NOT NULL,
    decision TEXT NOT NULL, policy_id TEXT NOT NULL, reason_codes TEXT NOT NULL,
    destination_class TEXT NOT NULL, data_labels TEXT NOT NULL, risk_signals TEXT NOT NULL,
    payload_fingerprint TEXT, execution_status TEXT NOT NULL,
    sequence INTEGER, previous_event_hash TEXT, current_event_hash TEXT, actor_uid TEXT
);
CREATE TABLE approvals (
    approval_id TEXT PRIMARY KEY, event_id TEXT NOT NULL, tool_name TEXT NOT NULL,
    requested_action TEXT NOT NULL, destination_class TEXT NOT NULL, status TEXT NOT NULL,
    created_at TEXT NOT NULL, reviewer TEXT, reviewed_at TEXT
);
"""


def _legacy_db(path: Path, count: int, duplicate: bool = False) -> list[dict]:
    conn = sqlite3.connect(path)
    conn.executescript(LEGACY_SCHEMA)
    previous = GENESIS_V1
    rows = []
    for i in range(1, count + 1):
        sequence = i - 1 if duplicate and i == count else i
        payload = {
            "event_id": f"legacy-{i}", "timestamp": f"2026-11-2{i % 9}T10:00:00+00:00",
            "tool_name": "send_email", "decision": "ALLOW", "policy_id": "p",
            "reason_codes": ["SAFE_ACTION"], "destination_class": "APPROVED", "data_labels": [],
            "risk_signals": [], "payload_fingerprint": None, "execution_status": "EXECUTED",
            "sequence": sequence, "actor_uid": None,
        }
        current = compute_event_hash(payload, previous)
        row = {**payload, "reason_codes": json.dumps(payload["reason_codes"]), "data_labels": "[]",
               "risk_signals": "[]", "previous_event_hash": previous, "current_event_hash": current}
        conn.execute(f"INSERT INTO audit_events ({','.join(row)}) VALUES ({','.join('?' for _ in row)})", list(row.values()))
        rows.append(row)
        previous = current
    conn.commit()
    conn.close()
    return rows


def test_legacy_database_migration_preserves_records(tmp_path: Path) -> None:
    path = tmp_path / "legacy.db"
    original = _legacy_db(path, 6)

    db = Database(path)
    stored = {r["event_id"]: r for r in _rows(db)}
    for row in original:
        for key, value in row.items():
            assert stored[row["event_id"]][key] == value, key
        assert stored[row["event_id"]]["chain_version"] is None

    with db.connection() as conn:
        migration = dict(conn.execute("SELECT * FROM audit_chain_migrations").fetchone())
    assert migration["legacy_event_count"] == 6
    assert migration["legacy_chain_consistent"] == 1
    assert migration["legacy_head_hash"] == original[-1]["current_event_hash"]

    new = AuditRepository(db).create(_event(1))
    assert (new.chain_version, new.sequence, new.previous_event_hash) == (2, 1, GENESIS_V2)

    report = _report(db)
    assert report["legacy"]["count"] == 6
    assert report["legacy"]["internally_consistent"] is True
    assert report["legacy"]["proves_historical_integrity"] is False
    assert report["verified"] == {"count": 1, "valid": True, "error": None}

    # Re-opening does not record a second migration.
    Database(path)
    with db.connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM audit_chain_migrations").fetchone()[0] == 1


def test_inconsistent_legacy_chain_is_reported_not_rewritten(tmp_path: Path) -> None:
    path = tmp_path / "legacy-dup.db"
    original = _legacy_db(path, 4, duplicate=True)
    db = Database(path)
    with db.connection() as conn:
        migration = dict(conn.execute("SELECT * FROM audit_chain_migrations").fetchone())
    assert migration["legacy_chain_consistent"] == 0
    assert "Duplicate sequence" in migration["legacy_chain_error"]
    assert sorted(r["current_event_hash"] for r in _rows(db)) == sorted(r["current_event_hash"] for r in original)
    AuditRepository(db).create(_event(1))
    report = _report(db)
    assert report["legacy"]["internally_consistent"] is False
    assert report["verified"]["valid"] is True
