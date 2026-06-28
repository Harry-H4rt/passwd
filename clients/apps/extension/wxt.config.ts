import { defineConfig } from "wxt";

// WXT generates the MV3 manifest. host_permissions lets the popup fetch the
// backend cross-origin without CORS (granted hosts bypass CORS in MV3). The
// origin is derived from WXT_API_BASE so a production build grants only the real
// API host. Export WXT_API_BASE (and WXT_VAULT_URL) when building for prod.
const API_BASE = process.env.WXT_API_BASE || "http://localhost:8080";
const API_ORIGIN = new URL(API_BASE).origin + "/*";

export default defineConfig({
  modules: ["@wxt-dev/module-react"],
  vite: () => ({
    plugins: [
      {
        // Vite stamps `crossorigin` on emitted <script>/<link>. On Firefox's
        // moz-extension:// pages that forces a CORS fetch of same-origin
        // extension files (no ACAO header) and the popup silently fails to load
        // → blank white popup. Strip it; Chrome works fine without it too.
        name: "passwd-strip-crossorigin",
        transformIndexHtml(html: string) {
          return html.replace(/ crossorigin/g, "");
        },
      },
    ],
  }),
  manifest: {
    name: "passwd",
    description: "Zero-knowledge password manager",
    permissions: ["storage", "clipboardWrite", "activeTab", "alarms"],
    host_permissions: [API_ORIGIN],
    action: {
      default_title: "passwd",
    },
    // Emitted only on the Firefox target: gives the add-on a stable id so Firefox
    // accepts it (temporary load + future signing). Dev id for now; AMO/signing
    // is a Phase 6 item.
    browser_specific_settings: {
      gecko: {
        id: "passwd@local.dev",
        strict_min_version: "121.0",
      },
    },
  },
});
