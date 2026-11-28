# Render Deployment Guide

Use `render.yaml`.

Configure:

- Python runtime
- `ENVIRONMENT=production`
- `DATABASE_MODE=firestore`
- `FIREBASE_AUTH_REQUIRED=true`
- Firebase project ID
- Google application credentials
- Strict CORS origin

Bind Uvicorn to `0.0.0.0` and use Render's `PORT`.

Do not store production audit data on Render's ephemeral filesystem.
