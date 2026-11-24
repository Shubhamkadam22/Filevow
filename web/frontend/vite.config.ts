import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// In development the dashboard runs on Vite (port 5173) and forwards API and
// WebSocket calls to the FileVow server, so cookies stay same-origin.
const backend = process.env.FILEVOW_BACKEND ?? "http://127.0.0.1:8443";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api/v1/events": { target: backend.replace(/^http/, "ws"), ws: true },
      "/api": { target: backend, changeOrigin: false },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
  },
});
