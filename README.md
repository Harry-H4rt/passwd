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

## Quick start

Run the backend and the web vault together (two terminals):

```bash
# 1) backend API on :8080
cd backend
PASSWD_DB=memory go run ./cmd/server      # or omit PASSWD_DB for a SQLite file

# 2) web vault on http://localhost:5173 (proxies /api -> :8080)
cd clients
npm install
npm -w @passwd/web run dev
```

Then open <http://localhost:5173>, click **Generate a private passphrase**, set a
master password, and create your account. Everything is encrypted in the browser;
the server only ever stores ciphertext.

### Tests

```bash
cd backend  && go test ./...                 # Go: crypto vectors + API integration
cd clients  && npm -w @passwd/crypto run test # TS: crypto + shared vectors
```

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the build plan and current status.
