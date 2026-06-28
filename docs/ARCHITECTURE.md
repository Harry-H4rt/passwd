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

- **Go backend (your requirement, and a good one):** simple deployment (single
  static binary), strong std-lib HTTP/TLS, excellent concurrency for a sync
  service. Go 1.22's `net/http.ServeMux` now does method + path routing, so we
  start with **zero external web dependencies**.
- **Not Wasp.sh:** Wasp generates a *Node* backend from a spec; it can't host a Go
  backend, and as "just a frontend" it adds coupling without benefit. Instead we
  use plain Vite + React so the **web vault and the extension share the same
  TypeScript crypto and API code** — the real architectural win.
- **WXT for the extension:** modern Manifest V3 tooling, Vite-based, supports
  React, cross-browser (Chrome/Firefox) from one codebase.
- **Astro for the site:** static, fast, simple; fully decoupled from the app.

## Backend layout (`/backend`)

```
cmd/server/main.go        wires config → storage → server, starts HTTP
internal/config/          env-based configuration
internal/server/          router, middleware, HTTP handlers (transport layer)
internal/auth/            registration, login, sessions/JWT, KDF params (domain)
internal/vault/           ciphers/folders sync (domain, operates on ciphertext)
internal/storage/         persistence interface + implementations (memory/SQL)
```

Dependencies point inward: `server` → (`auth`, `vault`) → `storage`. Storage is an
interface so we can start with an in-memory/SQLite impl and swap in Postgres for
SaaS without touching domain code.

## Single-tenant now, SaaS later

Per the decision to start single-tenant but grow into SaaS:

- Every domain row carries a `user_id` (and is ready for an `organization_id`)
  from day one, even while there's effectively one tenant.
- `storage.Store` is an interface; the SaaS path swaps the implementation and adds
  connection pooling, not new call sites.
- Auth issues stateless tokens (JWT) so horizontal scaling needs no shared session
  store (refresh tokens can live in the DB).
- Keep billing, org/team sharing, and admin out of the core until the
  single-tenant product is solid (see roadmap phases).

## API surface (implemented — Phase 2)

Auth routes are rate-limited per IP; vault routes require a bearer access token.
The `identifier` is the login handle (passphrase or email); the server blinds it
to an HMAC and never stores it in the clear.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET`  | `/healthz` | — | liveness |
| `POST` | `/api/accounts/prelogin` | — | returns KDF params for an `identifier` (defaults if unknown — no existence oracle) |
| `POST` | `/api/accounts/register` | — | create account (stores blinded identifier, KDF params, Argon2id verifier, Protected User Key) |
| `POST` | `/api/auth/login` | — | `identifier` + master-password-hash → access + refresh tokens, Protected User Key, KDF |
| `POST` | `/api/auth/refresh` | — | rotate refresh token → new token pair |
| `GET`  | `/api/sync` | bearer | full encrypted vault snapshot (`{ciphers: [...]}`) |
| `POST` | `/api/ciphers` | bearer | create opaque encrypted item |
| `PUT`  | `/api/ciphers/{id}` | bearer | update opaque encrypted item |
| `DELETE` | `/api/ciphers/{id}` | bearer | delete item |

> Tokens: stateless **HS256 JWT** access tokens (15 min) implemented with the Go
> std lib; opaque **refresh tokens** (30 d) stored hashed and rotated on every use.
