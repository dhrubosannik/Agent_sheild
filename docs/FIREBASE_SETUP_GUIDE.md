# Firebase Setup Guide

AgentShield uses an **existing shared Firebase project** owned by a teammate.
Do not create a new project and do not change its Project ID.

- Team roles, access and safe shared use: [FIREBASE_SHARED_TEAM_SETUP.md](FIREBASE_SHARED_TEAM_SETUP.md)
- Day-to-day setup (no Firebase / emulator / shared cloud): [FIREBASE_DEVELOPMENT_GUIDE.md](FIREBASE_DEVELOPMENT_GUIDE.md)

Never commit service-account JSON or private signing keys, and never put
Firebase Admin credentials in frontend (`VITE_*`) variables.
