import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ command }) => ({
  // VITE_* overrides are useful when serving the browser-only development
  // client, but must never be substituted into a packaged desktop bundle.
  envPrefix: command === "serve" ? "VITE_" : "DIFFTRAIL_DEV_ONLY_",
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    watch: {
      ignored: ["**/src-tauri/target/**", "**/src-tauri/gen/**"],
    },
  },
}));
