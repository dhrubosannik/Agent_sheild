"""SHA-256 hash-chain and signed-checkpoint helpers for audit integrity.

Two chain formats exist:

* **v1 (legacy)**: records written before Phase 13.2. Their hash covers every
  stored field except the hash fields. These records are retained unchanged;
  verifying them only shows internal consistency of what is stored now. v1
  sequence numbers were not unique-constrained and v1 rows could be updated,
  so a valid v1 chain is *not* proof of historical integrity.
* **v2 (verified)**: append-only records with database-enforced unique
  sequence numbers, serialized appends, and a hash over an explicit field
  list that includes ``chain_version``, ``event_type`` and
  ``related_event_id``. The v2 chain starts at ``GENESIS-V2``.
"""

import base64
from collections import Counter
import hashlib
import json
from typing import Any, Iterable

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

CHAIN_VERSION = 2
GENESIS_V1 = "GENESIS"
GENESIS_V2 = "GENESIS-V2"

HASH_FIELDS = {"current_event_hash", "previous_event_hash"}
# Fields that never participate in a v1 hash (added by later schema versions
# or derived at read time).
NON_V1_FIELDS = {"chain_version", "event_type", "related_event_id", "effective_execution_status"}
JSON_LIST_FIELDS = ("reason_codes", "data_labels", "risk_signals")

V2_FIELDS = (
    "event_id",
    "timestamp",
    "tool_name",
    "decision",
    "policy_id",
    "reason_codes",
    "destination_class",
    "data_labels",
    "risk_signals",
    "payload_fingerprint",
    "execution_status",
    "sequence",
    "actor_uid",
    "chain_version",
    "event_type",
    "related_event_id",
)


def canonical_json(payload: dict) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def compute_event_hash(payload: dict, previous_hash: str) -> str:
    integrity_payload = {**payload, "previous_event_hash": previous_hash}
    return hashlib.sha256(canonical_json(integrity_payload)).hexdigest()


def _decode_lists(payload: dict) -> dict:
    for key in JSON_LIST_FIELDS:
        value = payload.get(key)
        if isinstance(value, str):
            try:
                payload[key] = json.loads(value)
            except json.JSONDecodeError:
                payload[key] = [value]
    return payload


def v1_payload(event: dict) -> dict:
    payload = {
        key: value
        for key, value in event.items()
        if key not in HASH_FIELDS and key not in NON_V1_FIELDS
    }
    return _decode_lists(payload)


def v2_payload(event: dict) -> dict:
    return _decode_lists({key: event.get(key) for key in V2_FIELDS})


def event_chain_version(event: dict) -> int:
    version = event.get("chain_version")
    return int(version) if version is not None else 1


def verify_chain(
    events: Iterable[dict],
    version: int | None = None,
    expected_head: dict | None = None,
) -> tuple[bool, str | None]:
    """Verifies one chain segment.

    ``version`` defaults to the chain_version of the events (v1 when absent).
    ``expected_head`` ({"sequence": n, "current_event_hash": h}) lets callers
    detect truncation of the newest records, which a hash chain alone cannot.
    """
    items = list(events)
    if version is None:
        version = event_chain_version(items[0]) if items else 1
    genesis = GENESIS_V2 if version == CHAIN_VERSION else GENESIS_V1
    build = v2_payload if version == CHAIN_VERSION else v1_payload

    counts = Counter(int(event["sequence"]) for event in items)
    duplicates = sorted(seq for seq, count in counts.items() if count > 1)
    if duplicates:
        return False, f"Duplicate sequence {duplicates[0]}"

    previous_hash = genesis
    expected_sequence = 1
    for event in sorted(items, key=lambda item: int(item["sequence"])):
        sequence = int(event["sequence"])
        if sequence != expected_sequence:
            return False, f"Missing or reordered sequence at {sequence} (expected {expected_sequence})"
        if event_chain_version(event) != version:
            return False, f"Chain version mismatch at sequence {sequence}"
        if event.get("previous_event_hash") != previous_hash:
            return False, f"Previous hash mismatch at sequence {sequence}"
        current = compute_event_hash(build(event), previous_hash)
        if event.get("current_event_hash") != current:
            return False, f"Modified event at sequence {sequence}"
        previous_hash = current
        expected_sequence += 1

    if expected_head is not None:
        head_sequence = int(expected_head.get("sequence") or 0)
        if head_sequence != expected_sequence - 1:
            return False, (
                f"Chain head mismatch: state records sequence {head_sequence}, "
                f"records end at {expected_sequence - 1} (truncation or deletion)"
            )
        if head_sequence and expected_head.get("current_event_hash") != previous_hash:
            return False, "Chain head hash mismatch (truncation or substitution)"
    return True, None


def verify_audit_log(events: Iterable[dict], v2_head: dict | None = None) -> dict[str, Any]:
    """Splits records into legacy (v1) and verified (v2) segments and reports
    each separately. Legacy results are informational only."""
    legacy: list[dict] = []
    verified: list[dict] = []
    unsequenced = 0
    for event in events:
        if event.get("sequence") is None:
            unsequenced += 1
        elif event_chain_version(event) == CHAIN_VERSION:
            verified.append(event)
        else:
            legacy.append(event)

    legacy_valid, legacy_error = verify_chain(legacy, version=1) if legacy else (True, None)
    v2_valid, v2_error = verify_chain(verified, version=CHAIN_VERSION, expected_head=v2_head)
    return {
        "legacy": {
            "count": len(legacy),
            "unsequenced_count": unsequenced,
            "internally_consistent": legacy_valid,
            "error": legacy_error,
            "proves_historical_integrity": False,
        },
        "verified": {
            "count": len(verified),
            "valid": v2_valid,
            "error": v2_error,
        },
    }


def sign_checkpoint(checkpoint_payload: dict, private_key_pem: str) -> str:
    key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    data = canonical_json(checkpoint_payload)
    if isinstance(key, ed25519.Ed25519PrivateKey):
        signature = key.sign(data)
    elif isinstance(key, rsa.RSAPrivateKey):
        signature = key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    else:
        raise ValueError("Unsupported private signing key type")
    return base64.b64encode(signature).decode("ascii")


def verify_checkpoint_signature(checkpoint_payload: dict, signature: str, public_key_pem: str) -> bool:
    key = serialization.load_pem_public_key(public_key_pem.encode())
    data = canonical_json(checkpoint_payload)
    try:
        decoded = base64.b64decode(signature)
        if isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(decoded, data)
        elif isinstance(key, rsa.RSAPublicKey):
            key.verify(decoded, data, padding.PKCS1v15(), hashes.SHA256())
        else:
            return False
        return True
    except Exception:
        return False
