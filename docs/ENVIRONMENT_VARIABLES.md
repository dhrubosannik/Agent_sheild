# Environment Variables

Full annotated lists: `.env.example`, `.env.emulator.example`, `.env.cloud.example`,
`frontend/.env.example`, `frontend/.env.emulator.example`, `frontend/.env.cloud.example`.
See FIREBASE_DEVELOPMENT_GUIDE.md.

## Frontend (public, shipped to browsers)

- `VITE_API_BASE_URL`
- `VITE_FIREBASE_TARGET` (`none` | `emulator` | `cloud`)
- `VITE_FIREBASE_API_KEY`, `VITE_FIREBASE_AUTH_DOMAIN`, `VITE_FIREBASE_PROJECT_ID`, `VITE_FIREBASE_APP_ID`
- `VITE_FIREBASE_AUTH_EMULATOR_URL` (emulator only)
- `VITE_DEV_IDENTITY` (target `none` only)

Never put a service-account key or any Admin credential in frontend variables;
the build refuses to run if it detects one.

## Backend

- `AGENTSHIELD_ENV_FILE` (which env file to load; default `.env`)
- `FIREBASE_TARGET` (`none` | `emulator` | `cloud`)
- `FIREBASE_PROJECT_ID`, `FIREBASE_CLOUD_PROJECT_CONFIRM` (cloud, non-production)
- `GOOGLE_APPLICATION_CREDENTIALS` (cloud only; outside the repo; or ADC)
- `FIREBASE_AUTH_EMULATOR_HOST`, `FIRESTORE_EMULATOR_HOST` (emulator only)
- `FIREBASE_AUTH_REQUIRED`, `DATABASE_MODE`, `CORS_ORIGINS`, `MAX_REQUEST_BYTES`
- `RATE_LIMIT_BACKEND`, `RATE_LIMIT_SINGLE_INSTANCE`, `TRUSTED_PROXY_COUNT`
- `DEV_AUTH_IDENTITIES` (target `none` only; refused in production)

## Render

`FIREBASE_TARGET=cloud` is set in `render.yaml`; set `FIREBASE_PROJECT_ID`,
`GOOGLE_APPLICATION_CREDENTIALS` (secret file) and `CORS_ORIGINS` as Render
secrets. Never commit them.
