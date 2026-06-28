import { defineConfig } from "wxt";

// WXT generates the MV3 manifest. host_permissions lets the popup fetch the
// backend cross-origin without CORS (granted hosts bypass CORS in MV3). For a
// real deployment, replace localhost with the production API origin.
export default defineConfig({
  modules: ["@wxt-dev/module-react"],
  manifest: {
    name: "passwd",
    description: "Zero-knowledge password manager",
    permissions: ["storage", "clipboardWrite"],
    host_permissions: ["http://localhost:8080/*"],
    action: {
      default_title: "passwd",
    },
  },
});
