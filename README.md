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

Then open <http://localhost:5173>, click the **dice** in the identifier box to roll
a private passphrase, set a master password, and create your account. Everything is
encrypted in the browser; the server only ever stores ciphertext.

### Browser extension (Chrome & Firefox)

```bash
cd clients
npm -w @passwd/extension run build          # Chrome  -> apps/extension/.output/chrome-mv3
npm -w @passwd/extension run build:firefox  # Firefox -> apps/extension/.output/firefox-mv2
```

**Chrome:** `chrome://extensions` → enable **Developer mode** → **Load unpacked**
→ select `clients/apps/extension/.output/chrome-mv3`.

**Firefox:** `about:debugging#/runtime/this-firefox` → **Load Temporary Add-on…**
→ select `clients/apps/extension/.output/firefox-mv2/manifest.json`.
(Or `npm -w @passwd/extension run dev:firefox`, which auto-launches Firefox with
live reload.)

With the backend running, click the extension icon, unlock with your identifier +
master password, and your vault appears. The popup supports quick-access view/copy,
autofill, add/edit/delete, and a save-on-submit prompt when you log into a site.

### Tests

```bash
cd backend  && go test ./...                 # Go: crypto vectors + API integration
cd clients  && npm -w @passwd/crypto run test # TS: crypto + shared vectors
```

Two-factor (TOTP) can be enabled from the vault's **2FA** button; logins then
prompt for a code.

### Troubleshooting

**A change isn't showing up (a tweak appears to "revert" to the old version).**
The Vite dev server's file watcher can desync after a `git` branch switch or merge
and keep serving a stale bundle, so even a hard reload (Ctrl+Shift+R) shows the old
code. Restart the dev server:

```bash
# stop the running `npm -w @passwd/web run dev`, then start it again
cd clients && npm -w @passwd/web run dev
```

The same applies to the Astro `site` and the extension dev servers — if edits seem
ignored, restart the relevant dev process.

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the build plan and status, and
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) for production hardening and publishing
the extension to **AMO (Firefox)** and the **Chrome Web Store**.
