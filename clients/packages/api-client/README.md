# @passwd/api-client

The typed HTTP client shared by the web vault and the browser extension. It wraps
the Go backend's endpoints (see [`docs/ARCHITECTURE.md`](../../../docs/ARCHITECTURE.md))
and is responsible only for transport: it sends and receives the ciphertext
produced by `@passwd/crypto` and never handles plaintext secrets.

## What it provides

- A low-level transport module (`api.ts`) with one typed function per endpoint:
  `prelogin`, `register`, `login`, `refresh`, the TOTP and WebAuthn 2FA calls, the
  recovery endpoints, vault `sync`, and cipher CRUD.
- A higher-level session module (`session.ts`) that bridges the crypto library with
  the API — `registerAccount`, `loginAccount`, `loginWithPasskey`, `recoverAccount`,
  `loadVault`, `addItem`/`saveItem`/`removeItem`, `importItems`, and the 2FA and
  recovery enrollment helpers — exposing decrypted `VaultItem`s to the UI.

The base URL is configurable via `configureApi({ baseUrl })`: the web vault leaves
it empty (same-origin through the dev proxy or co-hosting), while the extension
points it at the backend host it lists in its permissions.

## Typecheck

```bash
npm install                              # from clients/ (workspaces)
npm -w @passwd/api-client run typecheck
```
