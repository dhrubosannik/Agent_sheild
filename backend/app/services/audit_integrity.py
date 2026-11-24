"""SHA-256 hash-chain and signed-checkpoint helpers for audit integrity."""

from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
from typing import Iterable

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa


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


def verify_chain(events: Iterable[dict]) -> tuple[bool, str | None]:
    previous_hash = "GENESIS"
    expected_sequence = 1
    for event in sorted(events, key=lambda item: item["sequence"]):
        sequence = int(event["sequence"])
        if sequence != expected_sequence:
            return False, f"Missing or reordered sequence at {sequence}"
        if event.get("previous_event_hash") != previous_hash:
            return False, f"Previous hash mismatch at sequence {sequence}"
        payload = {key: value for key, value in event.items() if key not in {"current_event_hash", "previous_event_hash"}}
        for key in ("reason_codes", "data_labels", "risk_signals"):
            value = payload.get(key)
            if isinstance(value, str):
                try:
                    payload[key] = json.loads(value)
                except json.JSONDecodeError:
                    payload[key] = [value]
        current = compute_event_hash(payload, previous_hash)
        if event.get("current_event_hash") != current:
            return False, f"Modified event at sequence {sequence}"
        previous_hash = current
        expected_sequence += 1
    return True, None


def sign_checkpoint(checkpoint_payload: dict, private_key_pem: str) -> str:
    key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    data = canonical_json(checkpoint_payload)
    if isinstance(key, ed25519.Ed25519PrivateKey):
        signature = key.sign(data)
    elif isinstance(key, rsa.RSAPrivateKey):
        signature = key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    else:
        raise ValueError("Unsupported private signing key type")
    return __import__("base64").b64encode(signature).decode("ascii")


def verify_checkpoint_signature(checkpoint_payload: dict, signature: str, public_key_pem: str) -> bool:
    import base64

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
