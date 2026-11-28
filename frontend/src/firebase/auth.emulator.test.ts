/**
 * End-to-end email verification against the Firebase Auth emulator, using the
 * real Firebase JS SDK and (when AGENTSHIELD_API_URL is set) the real backend.
 * Skipped unless FIREBASE_AUTH_EMULATOR_HOST is set.
 */
import { describe, expect, it } from "vitest";
import { initializeApp } from "firebase/app";
import {
  connectAuthEmulator,
  createUserWithEmailAndPassword,
  getAuth,
  sendEmailVerification,
} from "firebase/auth";
import { confirmEmailVerification, decodeTokenClaims } from "./auth";
import { createRequest } from "../api/client";

const HOST = process.env.FIREBASE_AUTH_EMULATOR_HOST;
const PROJECT = process.env.GCLOUD_PROJECT || "demo-agentshield";
const API = process.env.AGENTSHIELD_API_URL;

describe.skipIf(!HOST)("email verification against the Auth emulator", () => {
  it("refreshes the stale token so the backend accepts it", async () => {
    const app = initializeApp(
      { apiKey: "fake-api-key", authDomain: "localhost", projectId: PROJECT, appId: "1:1:web:1" },
      `e2e-${Date.now()}`,
    );
    const auth = getAuth(app);
    connectAuthEmulator(auth, `http://${HOST}`, { disableWarnings: true });

    const email = `vitest-${Date.now()}@agentshield.test`;
    const { user } = await createUserWithEmailAndPassword(auth, email, "Secure-Password-123");
    await sendEmailVerification(user);
    const getToken = (force?: boolean) => auth.currentUser!.getIdToken(force);
    const request = createRequest({ getToken, baseUrl: API || "" });

    expect(decodeTokenClaims(await user.getIdToken())?.email_verified).toBe(false);
    if (API) await expect(request("/api/v1/events")).rejects.toMatchObject({ status: 403 });

    // Click the verification link (emulator out-of-band code).
    const codes = await (await fetch(`http://${HOST}/emulator/v1/projects/${PROJECT}/oobCodes`)).json();
    const code = codes.oobCodes.filter((c: any) => c.email === email && c.requestType === "VERIFY_EMAIL").pop();
    const applied = await fetch(`http://${HOST}/identitytoolkit.googleapis.com/v1/accounts:update?key=fake-api-key`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ oobCode: code.oobCode }),
    });
    expect(applied.ok).toBe(true);

    // Stale: the cached token predates verification.
    expect(decodeTokenClaims(await user.getIdToken())?.email_verified).toBe(false);

    const outcome = await confirmEmailVerification(auth);
    expect(outcome.verified).toBe(true);

    // Subsequent (non-forced) token reads return the refreshed token.
    expect(decodeTokenClaims(await auth.currentUser!.getIdToken())?.email_verified).toBe(true);
    if (API) {
      const page = await request("/api/v1/events");
      expect(Array.isArray(page.items)).toBe(true);
    }
  }, 30000);
});
