import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import { findLeakedSecrets } from "./src/firebase/config.js";

export default defineConfig(({ mode }) => {
  // Every VITE_* value is shipped to browsers. Refuse to start or build if
  // anything resembling Firebase Admin / service-account credentials is set.
  const leaked = findLeakedSecrets(loadEnv(mode, process.cwd(), "VITE_"));
  if (leaked.length) {
    throw new Error(
      `Refusing to build: server credentials found in frontend variables (${leaked.join(", ")}). ` +
        "Firebase Admin credentials belong only to the backend.",
    );
  }
  return {
    plugins: [react()],
    test: {
      environment: "node",
      include: ["src/**/*.test.{js,jsx,ts,tsx}"],
    },
    server: {
      port: 5173,
      proxy: {
        "/api": "http://127.0.0.1:8000",
        "/health": "http://127.0.0.1:8000",
      },
    },
  };
});
