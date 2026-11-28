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
import { getFirebaseApp, firebaseConfigured } from "./firebase";

let cachedAuth: Auth | null = null;

export function getFirebaseAuth(): Auth | null {
  if (cachedAuth) return cachedAuth;
  const app = getFirebaseApp();
  if (!app) return null;
  cachedAuth = getAuth(app);
  const emulatorUrl =
    import.meta.env.VITE_FIREBASE_AUTH_EMULATOR_URL ||
    import.meta.env.VITE_FIREBASE_AUTH_EMULATOR_HOST ||
    (import.meta.env.VITE_USE_FIREBASE_EMULATOR === "true"
      ? "http://127.0.0.1:9099"
      : null);
  if (emulatorUrl) {
    const formatted = emulatorUrl.startsWith("http://") || emulatorUrl.startsWith("https://")
      ? emulatorUrl
      : `http://${emulatorUrl}`;
    connectAuthEmulator(cachedAuth, formatted, { disableWarnings: true });
  }
  return cachedAuth;
}

export async function registerWithEmail(email: string, password: string) {
  const auth = getFirebaseAuth();
  if (!auth) throw new Error("Firebase Authentication is not configured.");
  const credential = await createUserWithEmailAndPassword(auth, email, password);
  if (credential.user) {
    try {
      await sendEmailVerification(credential.user);
    } catch (err) {
      console.warn("Failed to send initial verification email:", err);
    }
  }
  return credential;
}

export async function sendVerificationEmail(user?: User | null) {
  const targetUser = user ?? getFirebaseAuth()?.currentUser;
  if (!targetUser) throw new Error("No active user session to send verification email to.");
  await sendEmailVerification(targetUser);
}

export async function reloadCurrentUser(): Promise<User | null> {
  const auth = getFirebaseAuth();
  const user = auth?.currentUser;
  if (!user) return null;
  await user.reload();
  return auth.currentUser;
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
