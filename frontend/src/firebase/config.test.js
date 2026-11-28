import { describe, expect, it } from "vitest";
import { findLeakedSecrets, readFirebaseEnv } from "./config.js";

const CLOUD = {
  VITE_FIREBASE_TARGET: "cloud",
  VITE_FIREBASE_API_KEY: "AIzaTestKeyOnly",
  VITE_FIREBASE_AUTH_DOMAIN: "shared-proj-123.firebaseapp.com",
  VITE_FIREBASE_PROJECT_ID: "shared-proj-123",
  VITE_FIREBASE_APP_ID: "1:123:web:abc",
};

describe("readFirebaseEnv", () => {
  it("defaults to no Firebase", () => {
    expect(readFirebaseEnv({})).toMatchObject({ target: "none", enabled: false, errors: [] });
  });

  it("never connects to the cloud without an explicit target", () => {
    const { VITE_FIREBASE_TARGET, ...withoutTarget } = CLOUD;
    const env = readFirebaseEnv(withoutTarget);
    expect(env.enabled).toBe(false);
    expect(env.warnings[0]).toMatch(/ignored because VITE_FIREBASE_TARGET=none/);
  });

  it("accepts a complete cloud configuration", () => {
    expect(readFirebaseEnv(CLOUD)).toMatchObject({ target: "cloud", enabled: true, errors: [], emulatorUrl: "" });
  });

  it("names each missing cloud variable", () => {
    const env = readFirebaseEnv({ VITE_FIREBASE_TARGET: "cloud", VITE_FIREBASE_PROJECT_ID: "shared-proj-123" });
    expect(env.enabled).toBe(false);
    expect(env.errors.join("\n")).toMatch(/VITE_FIREBASE_API_KEY is required/);
    expect(env.errors.join("\n")).toMatch(/VITE_FIREBASE_APP_ID is required/);
  });

  it("rejects placeholders and emulator mixing for the cloud", () => {
    expect(readFirebaseEnv({ ...CLOUD, VITE_FIREBASE_PROJECT_ID: "<shared-firebase-project-id>" }).errors.join()).toMatch(/placeholder/);
    expect(readFirebaseEnv({ ...CLOUD, VITE_FIREBASE_AUTH_EMULATOR_URL: "http://127.0.0.1:9099" }).errors.join()).toMatch(/must be empty/);
  });

  it("configures the emulator with local defaults", () => {
    const env = readFirebaseEnv({
      VITE_FIREBASE_TARGET: "emulator",
      VITE_FIREBASE_PROJECT_ID: "demo-agentshield",
      VITE_FIREBASE_AUTH_EMULATOR_URL: "127.0.0.1:9099",
    });
    expect(env).toMatchObject({ enabled: true, emulatorUrl: "http://127.0.0.1:9099" });
    expect(env.config.apiKey).toBe("demo-api-key");
  });

  it("requires the emulator URL and warns on non-demo emulator projects", () => {
    expect(readFirebaseEnv({ VITE_FIREBASE_TARGET: "emulator", VITE_FIREBASE_PROJECT_ID: "demo-x" }).errors.join()).toMatch(/EMULATOR_URL is required/);
    const env = readFirebaseEnv({ VITE_FIREBASE_TARGET: "emulator", VITE_FIREBASE_PROJECT_ID: "shared-proj-123", VITE_FIREBASE_AUTH_EMULATOR_URL: "http://127.0.0.1:9099" });
    expect(env.warnings.join()).toMatch(/not a demo-\* project/);
  });

  it("rejects unknown targets", () => {
    expect(readFirebaseEnv({ VITE_FIREBASE_TARGET: "prod" }).errors[0]).toMatch(/must be one of/);
  });
});

describe("findLeakedSecrets", () => {
  it("detects Admin credentials in frontend variables by name or value", () => {
    expect(findLeakedSecrets({ VITE_FIREBASE_PRIVATE_KEY: "x" })).toEqual(["VITE_FIREBASE_PRIVATE_KEY"]);
    expect(findLeakedSecrets({ VITE_GOOGLE_APPLICATION_CREDENTIALS: "/tmp/a.json" })).toHaveLength(1);
    expect(findLeakedSecrets({ VITE_X: '{"type": "service_account", "private_key": "..."}' })).toEqual(["VITE_X"]);
    expect(findLeakedSecrets({ VITE_X: "-----BEGIN PRIVATE KEY-----abc" })).toEqual(["VITE_X"]);
    expect(readFirebaseEnv({ ...CLOUD, VITE_SERVICE_ACCOUNT_JSON: "{}" }).enabled).toBe(false);
  });

  it("allows public web configuration", () => {
    expect(findLeakedSecrets(CLOUD)).toEqual([]);
  });
});
