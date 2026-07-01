import type { CapacitorConfig } from "@capacitor/cli";

// The mobile app is the web vault (apps/web) running inside a native WebView, so
// iOS and Android reuse the exact same crypto (WebCrypto + hash-wasm Argon2id)
// and API client — nothing security-critical is re-implemented natively.
//
// `webDir` is populated by scripts/mobile.sh, which builds the web app with the
// production API base baked in, then copies its dist here.
const config: CapacitorConfig = {
  // TODO: set your real reverse-DNS bundle id before submitting to the stores.
  // It is hard to change later (passkeys/app links bind to it).
  appId: "app.passwd.vault",
  appName: "passwd",
  webDir: "www",
  server: {
    // Android serves the app from https://localhost; iOS from
    // capacitor://localhost. Both origins are added to the backend's
    // PASSWD_ALLOWED_ORIGINS (render.yaml) so the API accepts them under CORS.
    androidScheme: "https",
  },
};

export default config;
