import {
  getAuth,
  sendPasswordResetEmail,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signOut,
  type User,
} from "firebase/auth";
import { getFirebaseApp, firebaseConfigured } from "./firebase";

export function getFirebaseAuth() {
  const app = getFirebaseApp();
  return app ? getAuth(app) : null;
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
