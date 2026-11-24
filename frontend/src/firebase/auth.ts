import {
  getAuth,
  connectAuthEmulator,
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
    (import.meta.env.VITE_USE_FIREBASE_EMULATOR === "true"
      ? "http://127.0.0.1:9099"
      : null);
  if (emulatorUrl) {
    connectAuthEmulator(cachedAuth, emulatorUrl, { disableWarnings: true });
  }
  return cachedAuth;
}

export async function registerWithEmail(email: string, password: string) {
  const auth = getFirebaseAuth();
  if (!auth) throw new Error("Firebase Authentication is not configured.");
  return createUserWithEmailAndPassword(auth, email, password);
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

export async function getCurrentIdToken(): Promise<string | null> {
  if (!firebaseConfigured) return null;
  const auth = getFirebaseAuth();
  const user: User | null = auth?.currentUser ?? null;
  return user ? user.getIdToken() : null;
}
