# Firestore Security Rules

The repository includes `firestore.rules`.

- Default deny.
- Browser users cannot create audit events.
- Browser users cannot modify policies.
- Browser users cannot create or delete approvals.
- Admin and reviewer roles can update approvals.
- Admin can manage users and policies.
- All reads require authentication.

The backend uses Firebase Admin SDK, which bypasses Security Rules. FastAPI must enforce every role and identity check.
