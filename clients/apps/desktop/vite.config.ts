import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The desktop app loads its built assets from Tauri's custom protocol, so asset
// references must be relative (base "./"), unlike the web vault (base "/"). The dev
// server runs on a fixed port that tauri.conf.json points at.
export default defineConfig({
  plugins: [react()],
  base: "./",
  clearScreen: false,
  server: { port: 1430, strictPort: true },
  build: { outDir: "dist", target: "es2021", sourcemap: false },
});
