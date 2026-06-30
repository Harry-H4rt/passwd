# passwd

A zero-knowledge, end-to-end-encrypted password manager. It consists of a **Go**
sync backend, a **web vault**, a **browser extension**, a standalone **offline
desktop app**, and a **marketing/download site**.

All encryption and decryption happen on the client. The server stores only
ciphertext it cannot read, along with the minimum needed to authenticate; it never
sees the master password, the vault contents, or even the plaintext account
identifier. The cryptographic design mirrors the published
[Bitwarden security whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/)
with two deliberate modernizations: **Argon2id** as the default key-derivation
function and **AES-256-GCM** (an AEAD) for item encryption. The full design is
documented in [`docs/CRYPTO.md`](docs/CRYPTO.md).

> **Security status: pre-audit.** The cryptographic design is documented but has
> **not** yet been independently audited. Do not store irreplaceable secrets in it
> until that review is complete.

## Features

- **Zero-knowledge encryption** — the server only ever holds opaque ciphertext.
- **Private by default** — register with a generated passphrase (no email, phone,
  or personal details) or opt in to an email; either way the identifier is stored
  only as a blinded HMAC.
- **Two-factor authentication** — TOTP and WebAuthn/passkeys, which can be used
  together.
- **Account recovery code** — an optional, user-controlled 24-word phrase to regain
  access after a forgotten master password. There is never a server-side reset.
- **Browser extension** — Chrome and Firefox, with autofill (strict domain
  matching), save-on-submit prompts, and full item management.
- **Standalone desktop app** — a separate, offline, KeePass-style vault whose data
  is a single portable encrypted file; no backend and no network.
- **Import and export** — encrypted backups plus plaintext JSON/CSV import that maps
  common managers (Bitwarden, Chrome, generic CSV).
- **Self-hostable** — a single static Go binary with SQLite, plus Docker and
  docker-compose.

## Repository layout

```
passwd/
├── backend/            Go sync API (standard-library HTTP, Go 1.22 routing)
│   ├── cmd/server/     main entrypoint
│   └── internal/       config, server, auth, vault, storage, crypto
├── clients/            TypeScript monorepo (npm workspaces)
│   ├── packages/
│   │   ├── crypto/     shared zero-knowledge crypto library
│   │   └── api-client/ shared typed API client
│   └── apps/
│       ├── web/        web vault SPA (Vite + React)
│       ├── extension/  browser extension (WXT, Manifest V3)
│       └── desktop/    standalone offline vault (Tauri v2)
├── site/               marketing + download site (Astro)
└── docs/               ARCHITECTURE, CRYPTO, DEPLOYMENT, ROADMAP
```

## Prerequisites

- **Go** 1.22.x for the backend (newer toolchains build it fine).
- **Node** 20+ and **npm** 10+ for the `clients/` and `site/` workspaces.
- For the desktop app only: the **Rust** toolchain and the Tauri system libraries
  (see [Desktop app](#desktop-app-standalone-and-offline)).

```bash
go version     # go1.22.x
node --version # v20 or newer
```

## Quick start

Install the JavaScript dependencies once — this covers every client workspace (web
vault, extension, desktop, and the shared crypto/api-client packages):

```bash
cd clients
npm install
```

Then run the two core processes in **two terminals** from the repository root.

```bash
# Terminal 1 — backend API on http://localhost:8080
cd backend
PASSWD_DB=memory go run ./cmd/server   # in-memory store (wiped on restart)
# To persist instead, omit PASSWD_DB; it defaults to a SQLite file at backend/data/passwd.db
```

```bash
# Terminal 2 — web vault on http://localhost:5173 (proxies /api -> :8080)
cd clients
npm -w @passwd/web run dev
```

Open <http://localhost:5173>, click the **dice** in the identifier box to generate
a private passphrase (or type an email), set a master password, and create your
account. Everything is encrypted in the browser before it reaches the server.

> To point the web vault at a backend on a different host or port, start it with
> `VITE_API_BASE=http://localhost:PORT npm -w @passwd/web run dev` and add that
> origin to the backend's `PASSWD_ALLOWED_ORIGINS`.

## Two-factor authentication and recovery

With the vault open, use the sidebar:

- **Two-factor (2FA)** — enroll a TOTP authenticator app; sign-in then asks for a
  code.
- **Passkeys** — register a passkey (Touch ID, Windows Hello, or a security key) as
  a phishing-resistant second factor. TOTP and passkeys can both be enabled; at
  sign-in you choose which to use.
- **Recovery code** — generate a 24-word recovery code, shown once. If you ever
  forget your master password, choose **Forgot your master password?** on the
  sign-in screen and use the recovery code to set a new one. The server cannot read
  the code and cannot reset the password on its own.

Passkeys work out of the box locally because the backend defaults to relying-party
ID `localhost` with origin `http://localhost:5173`. Without a physical
authenticator, open Chrome **DevTools → ⋮ → More tools → WebAuthn** and enable a
**virtual authenticator**, then enroll and sign in as normal.

## Browser extension (Chrome and Firefox)

```bash
cd clients
npm -w @passwd/extension run build          # Chrome  -> apps/extension/.output/chrome-mv3
npm -w @passwd/extension run build:firefox  # Firefox -> apps/extension/.output/firefox-mv2
```

- **Chrome:** `chrome://extensions` → enable **Developer mode** → **Load unpacked**
  → select `clients/apps/extension/.output/chrome-mv3`.
- **Firefox:** `about:debugging#/runtime/this-firefox` → **Load Temporary Add-on…**
  → select `clients/apps/extension/.output/firefox-mv2/manifest.json`. (Or
  `npm -w @passwd/extension run dev:firefox`, which auto-launches Firefox with live
  reload.)

With the backend running, click the extension icon, unlock with your identifier and
master password, and your vault appears. The popup supports view and copy, autofill,
add/edit/delete, and a save-on-submit prompt when you log in to a site.

## Desktop app (standalone and offline)

A separate, KeePass-style application with **no backend and no network**. The vault
is a single portable encrypted `.passwd` file you can keep anywhere, including a USB
stick, and the master password decrypts it directly. This is distinct from the web
vault and extension, which sync through the Go backend.

> There are no prebuilt downloads yet; signed cross-platform installers are produced
> by a release workflow once signing certificates are configured (see
> [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) and [`docs/ROADMAP.md`](docs/ROADMAP.md)).
> For now, build it yourself with the steps below.

**1. Install the build prerequisites** — [Node](https://nodejs.org) 20+, the
**Rust** toolchain, and (on Debian/Ubuntu) the Tauri system libraries:

```bash
# Rust toolchain (https://rustup.rs)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# Linux (Debian/Ubuntu) webview libraries
sudo apt update && sudo apt install libwebkit2gtk-4.1-dev build-essential \
  curl wget file libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev
```

**2. Build the app** from the `clients/` directory:

```bash
cd clients
npm install
npm -w @passwd/desktop run tauri build
```

**3. Install or run the result**, written to
`clients/apps/desktop/src-tauri/target/release/bundle/`:

```bash
# Option A — portable AppImage (no install; suitable for a USB stick)
chmod +x apps/desktop/src-tauri/target/release/bundle/appimage/passwd_*.AppImage
./apps/desktop/src-tauri/target/release/bundle/appimage/passwd_*.AppImage

# Option B — install system-wide via the .deb (adds it to your app menu)
sudo apt install ./apps/desktop/src-tauri/target/release/bundle/deb/passwd_*.deb
```

On first launch, choose **New vault…** to create a `.passwd` file (set a master
password) or **Open vault…** for an existing one. Add, edit, and copy entries,
generate passwords, and change the master password from the toolbar. The app
auto-locks when idle. **There is no account and no password reset** — if you lose
the master password the vault cannot be opened, so keep a backup of the file.

To develop with a hot-reloading window instead of a full build:

```bash
cd clients && npm -w @passwd/desktop run tauri dev
```

## Marketing and download site

```bash
cd site
npm install
npm run dev      # http://localhost:4321
```

## Tests

```bash
cd backend && go test ./...                  # Go: crypto vectors + API integration
cd clients && npm test --workspaces --if-present   # TypeScript: crypto + shared vectors
```

Continuous integration runs the equivalent build and test steps on every push and
pull request (see `.github/workflows/`).

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — system design, component
  responsibilities, and the full HTTP API surface.
- [`docs/CRYPTO.md`](docs/CRYPTO.md) — the cryptographic design and threat model.
- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) — production hardening, self-hosting,
  release builds, and store publishing.
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — the staged build plan and current status.

## Troubleshooting

**A change isn't showing up (an edit appears to "revert").** The Vite dev server's
file watcher can desync after a `git` branch switch or merge and keep serving a
stale bundle, so even a hard reload (Ctrl+Shift+R) shows old code. Restart the dev
server:

```bash
cd clients && npm -w @passwd/web run dev
```

The same applies to the Astro `site` and the extension dev servers — if edits seem
ignored, restart the relevant dev process.
