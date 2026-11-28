/**
 * Firebase web configuration, selected explicitly with VITE_FIREBASE_TARGET:
 *   none     - no Firebase (local development identities)
 *   emulator - local Auth emulator only
 *   cloud    - the shared Firebase project
 * Pure function so it can be tested without Vite.
 */

export const FIREBASE_TARGETS = ["none", "emulator", "cloud"];

const PLACEHOLDER = /(<|>|your[-_]|placeholder|changeme)/i;
// Anything that looks like server-side credentials must never reach the browser.
const SECRET_NAME = /(PRIVATE_KEY|SERVICE_ACCOUNT|CLIENT_SECRET|CREDENTIAL|ADMIN_SDK|GOOGLE_APPLICATION)/i;
const SECRET_VALUE = /(-----BEGIN [A-Z ]*PRIVATE KEY-----|"type"\s*:\s*"service_account"|"private_key")/;

export function findLeakedSecrets(env) {
  return Object.entries(env || {})
    .filter(([name, value]) => name.startsWith("VITE_") && (SECRET_NAME.test(name) || SECRET_VALUE.test(String(value ?? ""))))
    .map(([name]) => name);
}

export function readFirebaseEnv(env = {}) {
  const target = String(env.VITE_FIREBASE_TARGET || "none").trim().toLowerCase();
  const config = {
    apiKey: env.VITE_FIREBASE_API_KEY || "",
    authDomain: env.VITE_FIREBASE_AUTH_DOMAIN || "",
    projectId: env.VITE_FIREBASE_PROJECT_ID || "",
    appId: env.VITE_FIREBASE_APP_ID || "",
  };
  const emulatorRaw = env.VITE_FIREBASE_AUTH_EMULATOR_URL || env.VITE_FIREBASE_AUTH_EMULATOR_HOST || "";
  const emulatorUrl = emulatorRaw && !/^https?:\/\//.test(emulatorRaw) ? `http://${emulatorRaw}` : emulatorRaw;
  const errors = [];
  const warnings = [];

  const leaked = findLeakedSecrets(env);
  if (leaked.length) {
    errors.push(`Server credentials must never be in frontend variables: ${leaked.join(", ")}`);
  }

  if (!FIREBASE_TARGETS.includes(target)) {
    errors.push(`VITE_FIREBASE_TARGET must be one of ${FIREBASE_TARGETS.join(", ")} (got "${target}").`);
  } else if (target === "none") {
    if (config.projectId || config.apiKey) {
      warnings.push("Firebase web config is set but ignored because VITE_FIREBASE_TARGET=none.");
    }
  } else if (target === "emulator") {
    if (!config.projectId) errors.push("VITE_FIREBASE_PROJECT_ID is required (use demo-agentshield).");
    else if (!config.projectId.startsWith("demo-")) {
      warnings.push(`Emulator project "${config.projectId}" is not a demo-* project; use demo-agentshield.`);
    }
    if (!emulatorUrl) errors.push("VITE_FIREBASE_AUTH_EMULATOR_URL is required for the emulator (http://127.0.0.1:9099).");
    config.apiKey ||= "demo-api-key";
    config.authDomain ||= "localhost";
    config.appId ||= "1:000000000000:web:emulator";
  } else {
    const required = {
      VITE_FIREBASE_API_KEY: config.apiKey,
      VITE_FIREBASE_AUTH_DOMAIN: config.authDomain,
      VITE_FIREBASE_PROJECT_ID: config.projectId,
      VITE_FIREBASE_APP_ID: config.appId,
    };
    for (const [name, value] of Object.entries(required)) {
      if (!value) errors.push(`${name} is required for VITE_FIREBASE_TARGET=cloud.`);
      else if (PLACEHOLDER.test(value)) errors.push(`${name} still contains a placeholder; use the value supplied by the Firebase project owner.`);
    }
    if (emulatorUrl) errors.push("VITE_FIREBASE_AUTH_EMULATOR_URL must be empty for VITE_FIREBASE_TARGET=cloud.");
  }

  return {
    target,
    config,
    emulatorUrl: target === "emulator" ? emulatorUrl : "",
    errors,
    warnings,
    enabled: target !== "none" && FIREBASE_TARGETS.includes(target) && errors.length === 0,
  };
}
