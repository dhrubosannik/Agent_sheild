import { describe, expect, it, vi } from "vitest";
import { confirmEmailVerification, decodeTokenClaims } from "./auth";

function jwt(claims: Record<string, unknown>): string {
  const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${enc({ alg: "none" })}.${enc(claims)}.`;
}

/** Fake Firebase Auth whose cached token goes stale when the email is verified. */
function fakeAuth({ verifiedAfterReload = true, refreshedClaim = true } = {}) {
  let cached = jwt({ email_verified: false });
  const user: any = {
    emailVerified: false,
    reload: vi.fn(async () => {
      user.emailVerified = verifiedAfterReload;
    }),
    getIdToken: vi.fn(async (force?: boolean) => {
      if (force) cached = jwt({ email_verified: refreshedClaim });
      return cached;
    }),
  };
  return { auth: { currentUser: user } as any, user };
}

describe("decodeTokenClaims", () => {
  it("decodes base64url payloads", () => {
    expect(decodeTokenClaims(jwt({ email_verified: true, sub: "ü-1" }))).toEqual({ email_verified: true, sub: "ü-1" });
  });
  it("returns null for malformed tokens", () => {
    expect(decodeTokenClaims("nope")).toBeNull();
    expect(decodeTokenClaims(null)).toBeNull();
  });
});

describe("confirmEmailVerification", () => {
  it("force-refreshes the token after reload confirms verification", async () => {
    const { auth, user } = fakeAuth();
    expect(decodeTokenClaims(await user.getIdToken())?.email_verified).toBe(false); // stale

    const outcome = await confirmEmailVerification(auth);

    expect(user.reload).toHaveBeenCalledOnce();
    expect(user.getIdToken).toHaveBeenLastCalledWith(true);
    expect(outcome.verified).toBe(true);
    // Subsequent non-forced calls (used by the API client) get the refreshed token.
    expect(decodeTokenClaims(await user.getIdToken())?.email_verified).toBe(true);
  });

  it("does not refresh or mark verified when the email is still unverified", async () => {
    const { auth, user } = fakeAuth({ verifiedAfterReload: false });
    const outcome = await confirmEmailVerification(auth);
    expect(outcome).toMatchObject({ verified: false, reason: "NOT_VERIFIED" });
    expect(user.getIdToken).not.toHaveBeenCalled();
  });

  it("refuses to mark verified when the refreshed token still lacks the claim", async () => {
    const { auth } = fakeAuth({ refreshedClaim: false });
    expect(await confirmEmailVerification(auth)).toMatchObject({ verified: false, reason: "STALE_TOKEN" });
  });

  it("reports a missing session instead of assuming verification", async () => {
    expect(await confirmEmailVerification({ currentUser: null } as any)).toMatchObject({ verified: false, reason: "NO_SESSION" });
    expect(await confirmEmailVerification(null)).toMatchObject({ verified: false, reason: "NO_SESSION" });
  });
});
