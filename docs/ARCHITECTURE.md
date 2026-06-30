# Architecture

## System overview

```
┌─────────────────┐     ┌─────────────────┐     ┌──────────────────┐
│ Browser         │     │ Web vault       │     │ Marketing /      │
│ extension (MV3) │     │ SPA (Vite)      │     │ download site    │
│  WXT + React    │     │  React          │     │  (Astro)         │
└────────┬────────┘     └────────┬────────┘     └──────────────────┘
         │                       │
         │  share TS code:       │
         │  @passwd/crypto       │   ← zero-knowledge crypto (client only)
         │  @passwd/api-client   │   ← typed HTTP client
         │                       │
         └───────────┬───────────┘
                     │ HTTPS / JSON (only ciphertext crosses the wire)
                     ▼
          ┌─────────────────────┐
          │   Go sync backend   │   std-lib HTTP + Go 1.22 routing
          │  auth · vault · sync│
          └──────────┬──────────┘
                     ▼
          ┌─────────────────────┐
          │  PostgreSQL         │   (SQLite for local dev / self-host)
          │  stores ciphertext  │
          └─────────────────────┘
```

The single most important architectural fact: **all encryption and decryption
happen in the clients.** The Go backend is a high-integrity *sync and auth*
service that handles opaque encrypted blobs. See [`CRYPTO.md`](CRYPTO.md).

## Why this stack

- **Go backend:** simple deployment as a single static binary, a strong standard
  library for HTTP and TLS, and good concurrency for a sync service. Go 1.22's
  `net/http.ServeMux` provides method and path routing, so the backend ships with
  **no external web framework dependencies**.
- **Vite + React clients:** a plain SPA (rather than a generated full-stack
  framework) lets the **web vault and the browser extension share the same
  TypeScript crypto and API-client code**, which is the central architectural goal.
- **WXT for the extension:** modern Manifest V3 tooling, Vite-based, React support,
  and a single cross-browser (Chrome and Firefox) codebase.
- **Astro for the site:** static, fast, and fully decoupled from the application.
- **Tauri for the desktop app:** a separate, standalone, offline vault (no backend,
  no network) that reuses `@passwd/crypto`; the vault is a single portable
  encrypted file.

## Backend layout (`/backend`)

```
cmd/server/main.go        wires config → storage → server, starts HTTP
internal/config/          env-based configuration
internal/server/          router, middleware, HTTP handlers (transport layer)
internal/auth/            registration, login, sessions/JWT, KDF params (domain)
internal/vault/           ciphers/folders sync (domain, operates on ciphertext)
internal/storage/         persistence interface + implementations (memory/SQLite/Postgres)
internal/crypto/          Go reference impl used to cross-check the TS test vectors
```

Dependencies point inward: `server` → (`auth`, `vault`) → `storage`. Storage is an
interface with in-memory, SQLite, and PostgreSQL implementations that share one set
of contract tests; selecting Postgres (a `postgres://` `PASSWD_DB`) for a SaaS
deployment is a config change, not a code change in the domain layer.

## Single-tenant now, SaaS later

The system is designed to start single-tenant and grow into a multi-tenant SaaS
without a rewrite:

- Every domain row carries a `user_id` (and is ready for an `organization_id`)
  from day one, even while there's effectively one tenant.
- `storage.Store` is an interface; the SaaS path swaps the implementation and adds
  connection pooling, not new call sites.
- Auth issues stateless tokens (JWT) so horizontal scaling needs no shared session
  store (refresh tokens can live in the DB).
- Keep billing, org/team sharing, and admin out of the core until the
  single-tenant product is solid (see roadmap phases).

## API surface

Auth and recovery routes are rate-limited per IP; routes marked **bearer** require
a valid access token. The `identifier` is the login handle (passphrase or email);
the server blinds it to an HMAC and never stores it in the clear.

### Accounts and authentication

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET`  | `/healthz` | — | liveness |
| `POST` | `/api/accounts/prelogin` | — | returns KDF params for an `identifier` (defaults if unknown — no existence oracle) |
| `POST` | `/api/accounts/register` | — | create account (stores blinded identifier, KDF params, Argon2id verifier, Protected User Key) |
| `POST` | `/api/auth/login` | — | `identifier` + master-password-hash → tokens, Protected User Key, KDF (or a second-factor challenge) |
| `POST` | `/api/auth/refresh` | — | rotate refresh token → new token pair |

### Two-factor authentication

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET`  | `/api/2fa` | bearer | TOTP status |
| `POST` | `/api/2fa/setup` · `/enable` · `/disable` | bearer | enroll, confirm, and remove TOTP |
| `GET` / `DELETE` | `/api/2fa/webauthn/credentials[/{id}]` | bearer | list / remove passkeys |
| `POST` | `/api/2fa/webauthn/register/begin` · `/finish` | bearer | enroll a passkey |
| `POST` | `/api/auth/webauthn/begin` · `/finish` | — | passkey assertion at sign-in (password re-verified) |

### Account recovery

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET`  | `/api/recovery` | bearer | recovery-code status |
| `POST` | `/api/recovery/enable` · `/disable` | bearer | store / clear the recovery-wrapped key and verifier |
| `POST` | `/api/auth/recovery/challenge` | — | fetch the recovery-wrapped key for an identifier (decoy if unknown) |
| `POST` | `/api/auth/recovery/complete` | — | prove the recovery code and rotate to a new master password |

### Vault sync

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET`  | `/api/audit` | bearer | the caller's recent security events (audit log) |
| `GET`  | `/api/sync` | bearer | full encrypted vault snapshot (`{ciphers: [...]}`) |
| `POST` | `/api/ciphers` | bearer | create an opaque encrypted item |
| `PUT`  | `/api/ciphers/{id}` | bearer | update an opaque encrypted item |
| `DELETE` | `/api/ciphers/{id}` | bearer | delete an item |

### Item sharing (1:1)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET`  | `/api/users/public-key?identifier=…` | bearer | a recipient's sharing public key (by identifier) |
| `POST` | `/api/shares` | bearer | share an item: `{recipientIdentifier, wrappedKey, data}` (both opaque) |
| `GET`  | `/api/shares` | bearer | items shared **to** the caller (the item key is wrapped to their public key) |
| `DELETE` | `/api/shares/{id}` | bearer | remove a share (owner or recipient) |

> Tokens: stateless **HS256 JWT** access tokens (15 min) implemented with the Go
> standard library; opaque **refresh tokens** (30 d) stored hashed and rotated on
> every use. Login enforces a per-account lockout and shares it with the recovery
> flow.
