import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In dev the SPA is served from :5173 and proxies API calls to the Go backend on
// :8080, so requests are same-origin and no backend CORS config is needed.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": "http://localhost:8080",
      "/healthz": "http://localhost:8080",
    },
  },
});
