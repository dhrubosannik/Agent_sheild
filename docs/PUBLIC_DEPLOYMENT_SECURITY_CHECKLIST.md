# Public Deployment Security Checklist

- [ ] Firebase project created
- [ ] Email/Password provider configured
- [ ] First administrator securely provisioned
- [ ] Custom claims or role records enforced
- [ ] Backend verifies every Firebase ID token
- [ ] Render service uses HTTPS
- [ ] Vercel CORS origin is the only allowed frontend origin
- [ ] Firestore rules deployed and emulator-tested
- [ ] Admin SDK authorization enforced in FastAPI
- [ ] SQLite migration validated
- [ ] Audit chain verification passes
- [ ] Signed external checkpoints configured
- [ ] Private signing and service-account keys kept outside source control
- [ ] Rate limiting and request-size limits verified
- [ ] Secret-safe logging verified

Public deployment remains blocked until critical authentication, authorization, database access and audit integrity checks pass.
