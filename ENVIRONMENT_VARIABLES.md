# Environment Variables

## Frontend

- `VITE_API_BASE_URL`
- `VITE_FIREBASE_API_KEY`
- `VITE_FIREBASE_AUTH_DOMAIN`
- `VITE_FIREBASE_PROJECT_ID`
- `VITE_FIREBASE_APP_ID`

Frontend variables except the API URL are public Firebase web configuration. Never put a service-account private key in frontend variables.

## Backend

- `FIREBASE_PROJECT_ID`
- `GOOGLE_APPLICATION_CREDENTIALS`
- `FIREBASE_AUTH_REQUIRED`
- `FIREBASE_AUTH_EMULATOR_HOST`
- `FIRESTORE_EMULATOR_HOST`
- `DATABASE_MODE`
- `CORS_ORIGINS`
- `MAX_REQUEST_BYTES`

## Render

Use Render secrets for credentials and private signing keys. Never commit them.
