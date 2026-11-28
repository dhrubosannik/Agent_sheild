import {
  getAuth,
  connectAuthEmulator,
  sendEmailVerification,
  sendPasswordResetEmail,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signOut,
  type Auth,
  type User,
} from "firebase/auth";
import { getFirebaseApp, firebaseConfigured, firebaseEnv } from "./firebase";

let cachedAuth: Auth | null = null;

export function getFirebaseAuth(): Auth | null {
  if (cachedAuth) return cachedAuth;
  const app = getFirebaseApp();
  if (!app) return null;
  cachedAuth = getAuth(app);
  // Connect to the emulator only when VITE_FIREBASE_TARGET=emulator; a cloud
  // configuration can never be redirected to (or mixed with) the emulator.
  if (firebaseEnv.target === "emulator" && firebaseEnv.emulatorUrl) {
    connectAuthEmulator(cachedAuth, firebaseEnv.emulatorUrl, { disableWarnings: true });
  }
  return cachedAuth;
}

export interface RegistrationResult {
  user: User;
  verificationEmailSent: boolean;
}

export async function registerWithEmail(email: string, password: string): Promise<RegistrationResult> {
  const auth = getFirebaseAuth();
  if (!auth) throw new Error("Firebase Authentication is not configured.");
  const credential = await createUserWithEmailAndPassword(auth, email, password);
  let verificationEmailSent = false;
  try {
    await sendEmailVerification(credential.user);
    verificationEmailSent = true;
  } catch (err) {
    console.warn("Failed to send initial verification email:", err);
  }
  return { user: credential.user, verificationEmailSent };
}

export async function sendVerificationEmail(user?: User | null) {
  const targetUser = user ?? getFirebaseAuth()?.currentUser;
  if (!targetUser) throw new Error("No active user session to send verification email to.");
  await sendEmailVerification(targetUser);
}

export async function reloadCurrentUser(auth: Auth | null = getFirebaseAuth()): Promise<User | null> {
  const user = auth?.currentUser;
  if (!user) return null;
  await user.reload();
  return auth?.currentUser ?? null;
}

/** Decodes (without verifying) the payload of a Firebase ID token. */
export function decodeTokenClaims(token: string | null | undefined): Record<string, unknown> | null {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length < 2) return null;
  try {
    const base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
    const json =
      typeof atob === "function"
        ? decodeURIComponent(
            Array.from(atob(padded), (c) => `%${c.charCodeAt(0).toString(16).padStart(2, "0")}`).join(""),
          )
        : Buffer.from(padded, "base64").toString("utf8");
    return JSON.parse(json);
  } catch {
    return null;
  }
}

export type VerificationOutcome =
  | { verified: true; user: User; token: string }
  | { verified: false; user: User | null; reason: "NO_SESSION" | "NOT_VERIFIED" | "STALE_TOKEN" };

/**
 * Confirms email verification for the signed-in user.
 *
 * 1. Reloads the user record from Firebase.
 * 2. Only if `emailVerified === true`, force-refreshes the ID token. A token
 *    minted before verification still carries `email_verified: false`, and
 *    the backend rejects it; `getIdToken(true)` replaces Firebase's cached
 *    token, so every later `getIdToken()` call (used by the API client)
 *    returns the refreshed one.
 * 3. Reports success only when the refreshed token itself says
 *    `email_verified: true`. The user is never marked verified otherwise.
 */
export async function confirmEmailVerification(
  auth: Auth | null = getFirebaseAuth(),
): Promise<VerificationOutcome> {
  if (!auth?.currentUser) return { verified: false, user: null, reason: "NO_SESSION" };
  const refreshed = await reloadCurrentUser(auth);
  if (!refreshed) return { verified: false, user: null, reason: "NO_SESSION" };
  if (refreshed.emailVerified !== true) return { verified: false, user: refreshed, reason: "NOT_VERIFIED" };
  const token = await refreshed.getIdToken(true);
  if (decodeTokenClaims(token)?.email_verified !== true) {
    return { verified: false, user: refreshed, reason: "STALE_TOKEN" };
  }
  return { verified: true, user: refreshed, token };
}

export async function loginWithEmail(email: string, password: string) {
  const auth = getFirebaseAuth();
  if (!auth) throw new Error("Firebase Authentication is not configured.");
  return signInWithEmailAndPassword(auth, email, password);
}

export async function logoutFirebase() {
  const auth = getFirebaseAuth();
  if (auth) await signOut(auth);
}

export async function resetPassword(email: string) {
  const auth = getFirebaseAuth();
  if (!auth) throw new Error("Firebase Authentication is not configured.");
  await sendPasswordResetEmail(auth, email);
}

export async function getCurrentIdToken(forceRefresh: boolean = false): Promise<string | null> {
  if (!firebaseConfigured) return null;
  const auth = getFirebaseAuth();
  const user: User | null = auth?.currentUser ?? null;
  return user ? user.getIdToken(forceRefresh) : null;
}
