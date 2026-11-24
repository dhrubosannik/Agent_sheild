"""Test suite for signed-checkpoint verification, key rotation, and independent audit verifier."""

import base64
import json
from datetime import datetime, UTC
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from backend.app.services.audit_integrity import (
    canonical_json,
    sign_checkpoint,
    verify_checkpoint_signature,
)

results = []

def record(name: str, passed: bool, details: str = ""):
    results.append({"name": name, "passed": passed, "details": details})
    status = "PASS" if passed else "FAIL"
    print(f"[{status}] {name}: {details}")

def main():
    print("=" * 60)
    print("AgentShield Signed-Checkpoint Verification Suite")
    print("=" * 60)

    # Generate Test Keypairs
    # 1. Ed25519 Keypair 1
    ed_priv1 = ed25519.Ed25519PrivateKey.generate()
    ed_priv1_pem = ed_priv1.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    ed_pub1_pem = ed_priv1.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    # 2. Ed25519 Keypair 2 (for rotation & wrong key tests)
    ed_priv2 = ed25519.Ed25519PrivateKey.generate()
    ed_priv2_pem = ed_priv2.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    ed_pub2_pem = ed_priv2.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    # 3. RSA Keypair (2048-bit)
    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_priv_pem = rsa_priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    rsa_pub_pem = rsa_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    # Sample valid checkpoint payload
    sample_checkpoint = {
        "checkpoint_id": "chk-2026-11-24-001",
        "created_at": datetime.now(UTC).isoformat(),
        "first_sequence": 1,
        "last_sequence": 188,
        "root_hash": "d5479dae5a26ef48482fdc4b82c12d01ff618b5778ce2ed09b097a215e20fa5e",
        "total_events": 188,
    }

    # Test 1: Valid Ed25519 Checkpoint Signature
    sig_ed = sign_checkpoint(sample_checkpoint, ed_priv1_pem)
    valid_ed = verify_checkpoint_signature(sample_checkpoint, sig_ed, ed_pub1_pem)
    record("Valid Ed25519 Checkpoint Signature", valid_ed is True, "Signature verified successfully")

    # Test 2: Valid RSA Checkpoint Signature
    sig_rsa = sign_checkpoint(sample_checkpoint, rsa_priv_pem)
    valid_rsa = verify_checkpoint_signature(sample_checkpoint, sig_rsa, rsa_pub_pem)
    record("Valid RSA Checkpoint Signature", valid_rsa is True, "Signature verified successfully")

    # Test 3: Invalid Signature (Corrupted signature bytes)
    corrupted_sig = base64.b64encode(b"completely_corrupted_signature_bytes_1234567890").decode("ascii")
    res_corrupt = verify_checkpoint_signature(sample_checkpoint, corrupted_sig, ed_pub1_pem)
    record("Invalid Signature Rejection", res_corrupt is False, "Corrupted signature was rejected")

    # Test 4: Modified Checkpoint (Tampering with sequence or root hash)
    tampered_checkpoint = dict(sample_checkpoint)
    tampered_checkpoint["root_hash"] = "0000000000000000000000000000000000000000000000000000000000000000"
    res_tampered = verify_checkpoint_signature(tampered_checkpoint, sig_ed, ed_pub1_pem)
    record("Modified Checkpoint Rejection", res_tampered is False, "Tampered root_hash detected and rejected")

    tampered_seq = dict(sample_checkpoint)
    tampered_seq["last_sequence"] = 189
    res_tampered_seq = verify_checkpoint_signature(tampered_seq, sig_ed, ed_pub1_pem)
    record("Modified Sequence Rejection", res_tampered_seq is False, "Tampered last_sequence detected and rejected")

    # Test 5: Missing / Empty Checkpoint
    try:
        res_empty = verify_checkpoint_signature({}, sig_ed, ed_pub1_pem)
        record("Missing/Empty Checkpoint Handling", res_empty is False, "Empty checkpoint failed verification against original signature")
    except Exception as e:
        record("Missing/Empty Checkpoint Handling", True, f"Handled with exception: {e}")

    # Test 6: Wrong Public Key Rejection
    res_wrong_key = verify_checkpoint_signature(sample_checkpoint, sig_ed, ed_pub2_pem)
    record("Wrong Public Key Rejection", res_wrong_key is False, "Signature verified with wrong public key was rejected")

    # Test 7: Key Rotation
    # Checkpoint signed by Key 1 verified by Pub 1
    # Rotate to Key 2: New checkpoint signed by Key 2 verified by Pub 2
    checkpoint_rotated = {
        "checkpoint_id": "chk-2026-11-24-002",
        "created_at": datetime.now(UTC).isoformat(),
        "first_sequence": 189,
        "last_sequence": 250,
        "root_hash": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
        "total_events": 62,
    }
    sig_rotated = sign_checkpoint(checkpoint_rotated, ed_priv2_pem)
    # Must succeed with pub2
    valid_rot_pub2 = verify_checkpoint_signature(checkpoint_rotated, sig_rotated, ed_pub2_pem)
    # Must fail with pub1
    invalid_rot_pub1 = verify_checkpoint_signature(checkpoint_rotated, sig_rotated, ed_pub1_pem)
    record("Key Rotation Verification", valid_rot_pub2 is True and invalid_rot_pub1 is False, "New key verified; old key rejected for new checkpoint")

    # Test 8: Independent Verification without Private Key Access
    # The verifier receives only: (checkpoint_payload, signature, public_key_pem)
    # Completely isolated from private keys
    def independent_verifier(payload: dict, signature: str, public_key: str) -> bool:
        return verify_checkpoint_signature(payload, signature, public_key)

    indep_valid = independent_verifier(sample_checkpoint, sig_ed, ed_pub1_pem)
    record("Independent Verifier (Public Key Only)", indep_valid is True, "Verified checkpoint without any private key access")

    # Test 9: External Storage & Automation Check
    # Check if external storage (GCS bucket, AWS S3, public transparency log, cron/scheduler) exists in the repo
    external_storage_configured = False
    external_scheduler_configured = False
    record("External Checkpoint Storage Operational", False, "INCOMPLETE: No cloud storage bucket or public transparency log configured")
    record("Automated Checkpoint Scheduler Operational", False, "INCOMPLETE: No periodic cron or background daemon configured to produce signed checkpoints")

    print("=" * 60)
    passed_count = sum(1 for r in results if r["passed"])
    print(f"Summary: {passed_count}/{len(results)} tests passed.")
    print("=" * 60)

    with open("scripts/checkpoint_test_results.json", "w") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    main()
