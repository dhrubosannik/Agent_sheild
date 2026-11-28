# Audit Integrity Design

## Hash Chain

Each integrity-enabled event contains:

- Sequence number
- Previous event hash
- Current event hash

The current hash is SHA-256 over canonical JSON containing integrity-relevant event fields and the previous hash.

## Verification

Run:

```bash
.venv/bin/python scripts/verify_audit_integrity.py
```

The verifier detects modified events, missing sequence values, reordered chains, and previous-hash mismatches.

## Signed Checkpoints

Production checkpoints should sign sequence and chain-hash payloads with a private Ed25519 or RSA key kept outside Firestore. Public verification keys remain separately managed. Checkpoints are not yet provisioned by this local implementation.
