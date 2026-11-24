# Firebase/Render/Vercel Deployment Guide

## Backend on Render

Deploy using `render.yaml`.

Required Render variables:

- `ENVIRONMENT=production`
- `DATABASE_MODE=firestore`
- `FIREBASE_AUTH_REQUIRED=true`
- `FIREBASE_PROJECT_ID`
- `GOOGLE_APPLICATION_CREDENTIALS` or Render secure credential mechanism
- `CORS_ORIGINS=https://<vercel-domain>`

## Frontend on Vercel

Deploy `frontend`.

Set:

- `VITE_API_BASE_URL=https://<render-domain>`
- `VITE_FIREBASE_API_KEY`
- `VITE_FIREBASE_AUTH_DOMAIN`
- `VITE_FIREBASE_PROJECT_ID`
- `VITE_FIREBASE_APP_ID`

Do not public-deploy until authentication, role claims, Firestore rules, and audit verification are tested.
