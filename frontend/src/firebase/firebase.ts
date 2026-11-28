import { getApp, getApps, initializeApp, type FirebaseApp } from "firebase/app";
import { readFirebaseEnv } from "./config.js";

export const firebaseEnv = readFirebaseEnv(import.meta.env);

/** Firebase is used only when a target is explicitly selected and valid. */
export const firebaseConfigured = firebaseEnv.enabled;
/** Shown by the dashboard instead of silently falling back. */
export const firebaseConfigErrors: string[] = firebaseEnv.errors;

for (const warning of firebaseEnv.warnings) console.warn(`[AgentShield] ${warning}`);

export function getFirebaseApp(): FirebaseApp | null {
  if (!firebaseConfigured) return null;
  return getApps().length ? getApp() : initializeApp(firebaseEnv.config);
}
