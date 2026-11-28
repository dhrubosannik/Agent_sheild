# Email Verification Fix Report (Phase 13.2, Priority 1)

Date: 2026-11-28. Nothing was deployed. All Firebase testing used the local emulator project `demo-agentshield`.

## Finding 1.1: Stale ID token after email verification. **PASS**

**Original vulnerability.** Commit `9791375` made the backend reject tokens without `email_verified: true`. A user who verified their email kept sending the ID token minted *before* verification, which still says `email_verified: false`. The dashboard therefore received 403 on every request until Firebase refreshed the token (up to an hour) or the user signed in again.

**Root cause.** `frontend/src/api/client.js` called `getCurrentIdToken()` with no arguments. Nothing ever called `getIdToken(true)`, so Firebase's cached pre-verification token was reused. `user.reload()` updates the `User` object but not the ID token.

**Files changed**
- `frontend/src/firebase/auth.ts`: adds `confirmEmailVerification()` and `decodeTokenClaims()`. `registerWithEmail()` now reports whether the verification email was actually sent.
- `frontend/src/api/client.js`: adds `createRequest()`, which retries once with a force-refreshed token on 403 "Email verification is required".
- `frontend/src/components/AuthScreen.jsx`: uses `confirmEmailVerification()`.
- `frontend/src/App.jsx`: adds the `sessionVerified` state.

**Fix implemented**
1. `confirmEmailVerification()` reloads the user. Only if `emailVerified === true` does it call `getIdToken(true)`. It then decodes the refreshed token and reports success only if the token itself carries `email_verified: true`. Otherwise it returns `NOT_VERIFIED`, `STALE_TOKEN` or `NO_SESSION`.
2. `getIdToken(true)` replaces Firebase's cached token, so every later `getIdToken()` call made by the API client returns the refreshed token.
3. Safety net: if the backend still answers 403 "Email verification is required" (for example, the email was verified in another tab), the client force-refreshes once and retries. It never loops.

**Tests executed**

| Test | Type | Result |
|---|---|---|
| `src/firebase/auth.test.ts` (6 tests): forced refresh after reload, later cached reads get the refreshed token, no refresh when unverified, stale refreshed claim rejected, no session | vitest, fakes | 6/6 pass |
| `src/api/client.test.js` (5 tests): stale 403 → one forced-refresh retry, no infinite retry, other 403s not retried, dev-identity header, no client-supplied reviewer | vitest, fakes | 5/5 pass |
| `src/firebase/auth.emulator.test.ts`: **real Firebase JS SDK + Auth emulator + real backend (uvicorn, Firestore mode, auth required)**. Creates a user, gets 403, applies the emulator's verification code, confirms the cached token is still stale, runs `confirmEmailVerification()`, then the same client gets 200 | E2E | pass (backend log: 401 → 403 → 403 → 200) |
| `backend/tests/emulator/test_emulator_email_verification.py`: unverified token 403 → verified-but-stale token 403 → refreshed token 200; missing/invalid tokens 401; role claims picked up after refresh | pytest + emulator | 3/3 pass |

**Remaining limitations**
- Clicking through the UI in a real browser was **NOT TESTED** (no browser automation was run). The logic it calls is covered by the emulator end-to-end test above.
- The token is decoded on the client only to *decide what to show*. Authorization is enforced solely by the backend's Firebase Admin verification.

## Finding 1.2: Users marked verified without confirmation. **PASS**

**Original vulnerability.** `App.jsx` called `setFirebaseUser(verifiedUser || { ...getFirebaseAuth().currentUser, emailVerified: true })`. This forced `emailVerified: true` when user data was missing. It also copied the Firebase `User` into a plain object, which loses its methods.

**Root cause.** `user.reload()` mutates the same `User` object, so `setFirebaseUser(sameObject)` did not re-render. The fallback appears to have been a workaround for that.

**Fix implemented.**
- The fallback was removed.
- `App.jsx` tracks a separate `sessionVerified` flag. It is set from `onAuthStateChanged` (`user.emailVerified === true`), or by `onVerified()`, which only acts when it receives a user with `emailVerified === true` from a confirmed outcome.
- An unconfirmed user is never treated as verified.

**Files changed:** `frontend/src/App.jsx`

**Tests executed:** covered by the `confirmEmailVerification` unit tests (no success without confirmation) and the emulator end-to-end test. React state transitions in a browser: **NOT TESTED** (no DOM test environment installed).

**Remaining limitations:** none known beyond the browser click-through above.

## Finding 1.3: Misleading "verification email has been sent" message. **PASS**

**Original vulnerability.** The same message was shown:
- after sign-in with an unverified account, where no email is sent;
- on page load for an unverified user;
- after registration even when sending failed, because `registerWithEmail` only logged that failure.

**Fix implemented.** Messages are now centralized in `MESSAGES`:
- On sign-in or page load: "Your email address has not been verified yet…".
- After registration: "sent" only when `verificationEmailSent === true`; otherwise an explicit failure message with a resend hint.
- New messages for `STALE_TOKEN` and `NO_SESSION`.

**Files changed:** `frontend/src/components/AuthScreen.jsx`, `frontend/src/firebase/auth.ts`

**Tests executed:** `src/components/AuthScreen.test.jsx` (server-side render of an unverified returning user; message constants): 2/2 pass.

## Finding 1.4 (new, found during emulator testing): Firebase Admin initialization broken by `9791375`. **PASS**

**Original vulnerability.** `get_firebase_app()` gained a reference to `os` at its top, while still containing a later `import os` inside the function. Python treats `os` as a local name for the whole function, so the new first line raised `UnboundLocalError` whenever `FIREBASE_PROJECT_ID` was set. `get_authenticated_user` catches that as a generic exception and returns 401. **With commit `9791375`, every valid Firebase token was rejected.** The mocked unit tests did not exercise the real function.

**Files changed:** `backend/app/core/firebase.py` (removed the inner import), `backend/app/core/firestore.py` (removed a duplicate import).

**Tests executed:** `backend/tests/test_firebase_init_regression.py` (calls the real function, unmocked), plus every emulator test that verifies real tokens. All pass.
