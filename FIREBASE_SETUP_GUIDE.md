# Firebase Setup Guide

1. Create a Firebase project.
2. Enable Email/Password Authentication.
3. Create a Firestore database.
4. Create a service account or configure Application Default Credentials.
5. Set `FIREBASE_PROJECT_ID`.
6. Set `GOOGLE_APPLICATION_CREDENTIALS` to a local secret file outside source control, or use the Render secret environment mechanism.
7. Set frontend Firebase public configuration variables.
8. Start Firebase Emulator Suite for local auth and Firestore testing.
9. Deploy `firestore.rules` only after emulator tests pass.

Never commit service-account JSON or private signing keys.
