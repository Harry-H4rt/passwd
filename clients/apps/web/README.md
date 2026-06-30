# @passwd/web

The browser-based vault: a Vite + React single-page app that talks to the Go sync
backend. All encryption and decryption happen here, in the browser, via
`@passwd/crypto`; the backend only ever receives ciphertext. It shares that crypto
library and the typed `@passwd/api-client` with the browser extension.

## Features

- Register with a generated passphrase or an email, sign in, and unlock.
- Vault list with search; add, edit, and delete items; one-click copy.
- Built-in password generator.
- Two-factor authentication: TOTP and WebAuthn/passkeys.
- Account recovery code — a 24-word phrase to regain access after a forgotten
  master password (see [`docs/CRYPTO.md`](../../../docs/CRYPTO.md)).
- Encrypted backup export plus plaintext JSON/CSV import (Bitwarden, Chrome, and
  generic CSV mappings).
- Idle auto-lock that clears the in-memory keys; manual lock from the sidebar.
- Light and dark themes.

## Develop

Run from the `clients/` workspace root (dependencies are installed there):

```bash
cd clients
npm install
npm -w @passwd/web run dev        # http://localhost:5173 (proxies /api -> :8080)
npm -w @passwd/web run build      # static output in apps/web/dist/
npm -w @passwd/web run typecheck
```

The web vault expects the backend on `http://localhost:8080`. To point it
elsewhere, set `VITE_API_BASE` (see `.env.example`) and add that origin to the
backend's `PASSWD_ALLOWED_ORIGINS`.

See the repository [`README.md`](../../../README.md) for the full local-development
guide and [`docs/DEPLOYMENT.md`](../../../docs/DEPLOYMENT.md) for production builds.
