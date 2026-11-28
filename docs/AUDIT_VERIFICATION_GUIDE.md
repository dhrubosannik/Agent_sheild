# Audit Verification Guide

Local SQLite verification:

```bash
.venv/bin/python scripts/verify_audit_integrity.py
```

Exit success proves:

- Every sequence is present
- The sequence is ordered
- Previous hashes match
- Event hashes match their canonical payload

This is not cryptographic tamper-proofing against a privileged database administrator. Production checkpoints are required.
