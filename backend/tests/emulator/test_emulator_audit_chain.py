"""Firestore audit chain: concurrency, uniqueness, tampering, legacy coexistence."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

from google.api_core import exceptions as gexc
from google.cloud import firestore
import pytest

from backend.app.models.audit_event import AuditEvent
from backend.app.models.enums import DestinationClass, ExecutionStatus, SecurityDecision
from backend.app.services.audit_integrity import verify_audit_log
from backend.app.storage.firestore_audit_repository import FirestoreAuditRepository


def _event(i: int) -> AuditEvent:
    return AuditEvent(
        event_id=f"fs-evt-{i:04d}",
        timestamp=datetime.now(UTC),
        tool_name="send_email",
        decision=SecurityDecision.ALLOW,
        policy_id="default-allow-safe",
        reason_codes=["SAFE_ACTION"],
        destination_class=DestinationClass.APPROVED,
        execution_status=ExecutionStatus.EXECUTED,
    )


@pytest.fixture
def repo(firestore_client):
    return FirestoreAuditRepository(firestore_client)


def _report(repo):
    return verify_audit_log(repo.export_chain_records(), repo.chain_head())


def test_concurrent_appends_form_one_valid_chain(repo) -> None:
    with ThreadPoolExecutor(max_workers=8) as pool:
        created = list(pool.map(lambda i: repo.create(_event(i)), range(40)))
    assert sorted(e.sequence for e in created) == list(range(1, 41))
    ledger = repo.export_sequence_ledger()
    assert len(ledger) == 40 and len({d["id"] for d in ledger}) == 40
    assert _report(repo)["verified"] == {"count": 40, "valid": True, "error": None}


def test_existing_event_cannot_be_overwritten(repo) -> None:
    repo.create(_event(1))
    with pytest.raises((gexc.AlreadyExists, gexc.Conflict)):
        repo.create(_event(1))
    assert _report(repo)["verified"]["valid"] is True


def test_duplicate_sequence_document_is_rejected(repo, firestore_client) -> None:
    repo.create(_event(1))
    transaction = firestore_client.transaction()

    @firestore.transactional
    def forge(txn):
        txn.create(firestore_client.collection("audit_sequence_v2").document(f"{1:012d}"), {"event_id": "forged"})

    with pytest.raises((gexc.AlreadyExists, gexc.Conflict)):
        forge(transaction)


def test_status_change_appends_record(repo) -> None:
    original = repo.create(_event(1))
    assert repo.record_execution_status(original.event_id, ExecutionStatus.FAILED) is True
    fetched = repo.get_by_id(original.event_id)
    assert fetched.execution_status == ExecutionStatus.EXECUTED
    assert fetched.effective_execution_status == ExecutionStatus.FAILED
    assert _report(repo)["verified"]["count"] == 2


def test_privileged_tampering_is_detected(repo, firestore_client) -> None:
    for i in range(5):
        repo.create(_event(i))
    firestore_client.collection("audit_events").document("fs-evt-0002").update({"decision": "BLOCK"})
    assert "Modified event at sequence 3" in _report(repo)["verified"]["error"]


def test_privileged_deletion_is_detected(repo, firestore_client) -> None:
    for i in range(5):
        repo.create(_event(i))
    firestore_client.collection("audit_events").document("fs-evt-0001").delete()
    assert "Missing or reordered sequence" in _report(repo)["verified"]["error"]


def test_privileged_tail_deletion_is_detected(repo, firestore_client) -> None:
    for i in range(3):
        repo.create(_event(i))
    firestore_client.collection("audit_events").document("fs-evt-0002").delete()
    assert "Chain head mismatch" in _report(repo)["verified"]["error"]


def test_legacy_documents_are_reported_separately(repo, firestore_client) -> None:
    firestore_client.collection("audit_events").document("legacy-1").set(
        {"event_id": "legacy-1", "sequence": 1, "previous_event_hash": "GENESIS", "current_event_hash": "unverifiable"}
    )
    repo.create(_event(1))
    report = _report(repo)
    assert report["legacy"]["count"] == 1
    assert report["legacy"]["proves_historical_integrity"] is False
    assert report["verified"] == {"count": 1, "valid": True, "error": None}
    snapshot = firestore_client.collection("audit_events").document("legacy-1").get().to_dict()
    assert "chain_version" not in snapshot  # legacy document untouched


_WORKER = """
import os, sys
from datetime import UTC, datetime
sys.path.insert(0, os.getcwd())
from backend.app.core.config import get_settings
get_settings.cache_clear()
from backend.app.models.audit_event import AuditEvent
from backend.app.models.enums import DestinationClass, ExecutionStatus, SecurityDecision
from backend.app.storage.firestore_audit_repository import FirestoreAuditRepository
repo = FirestoreAuditRepository()
worker = sys.argv[1]
for i in range(10):
    repo.create(AuditEvent(event_id=f"proc-{worker}-{i}", timestamp=datetime.now(UTC), tool_name="t",
        decision=SecurityDecision.ALLOW, policy_id="p", destination_class=DestinationClass.APPROVED,
        execution_status=ExecutionStatus.EXECUTED))
"""


def test_appends_from_separate_processes_form_one_valid_chain(repo) -> None:
    """Separate OS processes (like separate Render instances) do not share the
    in-process lock; Firestore transactions alone must serialize them."""
    import os
    import subprocess
    import sys

    procs = [
        subprocess.Popen([sys.executable, "-c", _WORKER, str(n)], env=dict(os.environ), cwd=os.getcwd())
        for n in range(3)
    ]
    assert [p.wait(timeout=300) for p in procs] == [0, 0, 0]
    report = _report(repo)
    assert report["verified"] == {"count": 30, "valid": True, "error": None}
    assert len(repo.export_sequence_ledger()) == 30
