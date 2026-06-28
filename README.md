# passwd

A zero-knowledge, end-to-end-encrypted password manager: a **Go** sync backend, a
**web vault**, and a **browser extension**, plus a marketing/download site.

The cryptographic design mirrors the audited [Bitwarden protocol](https://bitwarden.com/help/bitwarden-security-white-paper/)
(separation of authentication from encryption; the server only ever stores
ciphertext it cannot read) with two deliberate modernizations: **Argon2id** as the
default KDF and **AES-256-GCM** (AEAD) for item encryption.

> ⚠️ **Security status:** pre-alpha. The crypto design is documented in
> [`docs/CRYPTO.md`](docs/CRYPTO.md) but has **not** been independently audited.
> Do not store real secrets in it yet.

## Repository layout

```
passwd/
├── backend/            Go sync API (std-lib HTTP, Go 1.22 routing)
│   ├── cmd/server/     main entrypoint
│   └── internal/       config, server, auth, vault, storage
├── clients/            TypeScript monorepo (npm workspaces)
│   ├── packages/
│   │   ├── crypto/     ⭐ shared zero-knowledge crypto library (the heart)
│   │   └── api-client/ shared typed API client
│   └── apps/
│       ├── web/        web vault SPA (Vite)
│       └── extension/  browser extension (WXT, Manifest V3)
├── site/               marketing + download site
└── docs/               ARCHITECTURE.md, CRYPTO.md, ROADMAP.md
```

## Quick start (backend)

```bash
cd backend
go run ./cmd/server
# -> listening on :8080 ; try:  curl localhost:8080/healthz
```

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the build plan and current status.
