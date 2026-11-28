# Firebase Authentication Guide

The frontend uses Firebase Email/Password Authentication. The backend verifies Firebase ID tokens and reads the custom `role` claim.

Roles:

- ADMIN
- REVIEWER
- VIEWER

API requests use:

```text
Authorization: Bearer <FIREBASE_ID_TOKEN>
```

In local development, Firebase authentication can be disabled explicitly. In production, set `FIREBASE_AUTH_REQUIRED=true`.
