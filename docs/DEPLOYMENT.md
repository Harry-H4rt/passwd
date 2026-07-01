# Deployment & publishing

> ⚠️ Pre-audit. Do not host this for real users until the Phase 5 security audit
> gate passes (see ROADMAP). The steps below are the mechanics for when it does.

## Reference deployment: Cloudflare Pages + Render + Neon (card-free)

A concrete, no-custom-domain, **no-payment-method** setup you can stand up today.
The static pieces go on Cloudflare Pages (free); the backend runs as a free Render
web service backed by a free Neon Postgres — so the server is stateless (no disk)
and all data lives in Neon.

| Piece | Host | URL (example) | Build config |
|---|---|---|---|
| Marketing site (`site/`) | Cloudflare Pages | `https://passwd-site.pages.dev` | root `site`, build `npm ci && npm run build`, output `dist` |
| Web vault (`clients/apps/web`) | Cloudflare Pages | `https://passwd-vault.pages.dev` | root `clients`, build `npm ci && npm -w @passwd/web run build`, output `apps/web/dist` |
| Database | Neon (free Postgres) | `postgres://…neon.tech/passwd` | — |
| Backend (`backend/`) | Render (free web service) | `https://passwd-api.onrender.com` | `render.yaml` (Docker) |

Substitute your own project names (the `*.pages.dev`, `*.onrender.com`, and Neon
subdomains are globally unique). The URLs reference each other, so pick them first,
then plug them in. Free tradeoffs: the Render service **sleeps after ~15 min idle**
(first request cold-starts ~30-60s) and Neon autosuspends — fine for staging, not
for real users (which is gated on the audit anyway).

### 1. Database on Neon

1. Sign up at <https://neon.tech> (no card), create a project and a database named
   `passwd`.
2. Copy the **pooled** connection string. Ensure it ends with `?sslmode=require`,
   e.g. `postgres://user:pass@ep-xxx-pooler.eu-central-1.aws.neon.tech/passwd?sslmode=require`.
   You'll paste this as `PASSWD_DB` in the next step. The schema is created
   automatically on first boot.

### 2. Backend on Render

`render.yaml` (repo root) is a Blueprint for a free Docker web service. In Render:
New → **Blueprint** → connect this repo → apply. Then in the service's
**Environment** tab set the four `sync: false` vars:

- `PASSWD_DB` = your Neon URL from step 1
- `PASSWD_JWT_SECRET` = output of `openssl rand -hex 32`
- `PASSWD_IDENTIFIER_PEPPER` = output of a second `openssl rand -hex 32` —
  **permanent**, back it up; rotating it orphans every account
- (the CORS/passkey URLs are already in `render.yaml`; edit them there to your
  vault's `*.pages.dev` URL, or override per-env in the dashboard)

Render injects `PORT` and the server binds to it automatically (the Dockerfile no
longer pins `PASSWD_ADDR`). Once live, `https://passwd-api.onrender.com/healthz`
returns `{"status":"ok"}`.

Rate-limiting note: behind Render's proxy the app sees the proxy as the peer, so
`PASSWD_TRUSTED_PROXIES` stays unset and the per-IP limiter effectively keys on the
proxy. The **per-account login lockout is the real brute-force defense** and is
unaffected; raise `PASSWD_AUTH_RATELIMIT_PER_MIN` if legitimate users get limited.

> **Alternative — Fly.io (needs a card, no cold starts, ~<$1/mo):** `backend/fly.toml`
> is committed for the SQLite-on-a-volume path. From `backend/`: `fly auth login`;
> edit `app`/region; `fly volumes create passwd_data --region lhr --size 1`;
> `fly secrets set PASSWD_JWT_SECRET=$(openssl rand -hex 32) PASSWD_IDENTIFIER_PEPPER=$(openssl rand -hex 32)`;
> `fly deploy`. Update the CORS/passkey env in `fly.toml` to your vault URL first.

### 3. Web vault on Cloudflare Pages

Create a Pages project connected to this repo (Cloudflare dashboard → Workers &
Pages → Create → Pages → Connect to Git):

- **Root directory:** `clients`
- **Build command:** `npm ci && npm -w @passwd/web run build`
- **Build output directory:** `apps/web/dist`
- **Environment variables:**
  - `NODE_VERSION` = `20`
  - `VITE_API_BASE` = `https://passwd-api.onrender.com` (your backend URL)
  - `VITE_SITE_URL` = `https://passwd-site.pages.dev` (your marketing site URL)

`clients/apps/web/public/_redirects` (committed) gives the SPA its deep-link
fallback. Because the vault is a separate origin from the API, the backend's
`PASSWD_ALLOWED_ORIGINS` must list this exact URL (step 2).

### 4. Marketing site on Cloudflare Pages

A second Pages project from the same repo:

- **Root directory:** `site`
- **Build command:** `npm ci && npm run build`
- **Build output directory:** `dist`
- **Environment variables:**
  - `NODE_VERSION` = `20`
  - `PUBLIC_SITE_URL` = `https://passwd-site.pages.dev` (this site's own URL)
  - `PUBLIC_VAULT_URL` = `https://passwd-vault.pages.dev` (the web vault)
  - `PUBLIC_GITHUB_URL` = `https://github.com/Harry-H4rt/passwd`
  - `PUBLIC_RELEASES_URL` = `https://github.com/Harry-H4rt/passwd/releases/latest`

### 5. Verify end-to-end

1. `https://passwd-site.pages.dev` loads; "Open vault" → the vault URL; "Download" →
   GitHub releases.
2. `https://passwd-vault.pages.dev` loads and can create/unlock an account (this
   exercises CORS against the Render backend and the passkey RP config; the first
   request may cold-start the free Render service).
3. Swapping in a real domain later is just: point DNS at each host, update the
   `PUBLIC_*` / `VITE_*` / `PASSWD_*` URLs, and re-deploy. Note passkeys are bound
   to `PASSWD_WEBAUTHN_RP_ID`, so changing the vault's host invalidates any already
   enrolled passkeys.

The generic, host-agnostic mechanics for each piece follow below.

## Backend (production)

Set strong, **stable** secrets — the server refuses to boot in production with the
dev defaults:

| Env var | Notes |
|---|---|
| `PASSWD_ENV=production` | enables HSTS; enforces non-default secrets |
| `PASSWD_JWT_SECRET` | `openssl rand -hex 32` (or `PASSWD_JWT_SECRET_FILE`) |
| `PASSWD_IDENTIFIER_PEPPER` | `openssl rand -hex 32` (or `..._FILE`) — **never change it** (rotating orphans all accounts) |
| `PASSWD_DB` | SQLite file path, e.g. `/var/lib/passwd/passwd.db`, **or** a `postgres://…` URL to use PostgreSQL |
| `PASSWD_ALLOWED_ORIGINS` | your web-vault origin, e.g. `https://vault.example.com` |
| `PASSWD_ADDR` | listen address |
| `PASSWD_WEBAUTHN_RP_ID` | passkey Relying Party ID: web-vault host only, e.g. `vault.example.com` — set once, keep **stable** (passkeys bind to it) |
| `PASSWD_WEBAUTHN_RP_NAME` | name authenticators show at enrollment (default `passwd`) |
| `PASSWD_WEBAUTHN_RP_ORIGINS` | fully-qualified passkey ceremony origins, e.g. `https://vault.example.com` (defaults to `PASSWD_ALLOWED_ORIGINS`) |
| `PASSWD_TRUSTED_PROXIES` | comma-separated reverse-proxy IPs whose `X-Forwarded-For` is trusted for rate limiting. **Set this when behind a proxy** (below); otherwise the per-IP limiter sees only the proxy's IP. |

Passkeys are a **second factor** alongside TOTP, never passwordless. The RP ID must
be the registrable domain the web vault is served from; a passkey enrolled there
cannot be used from the browser extension's `chrome-extension://` origin, so the
extension uses TOTP (or links out to the vault) — see the web-vault section. If the
RP config is invalid the server still boots with passkeys disabled (TOTP and
password login are unaffected).

Terminate TLS in front of it (reverse proxy / load balancer). When you do, set
`PASSWD_TRUSTED_PROXIES` to the proxy's IP(s) so the per-IP rate limiter keys off
the real client IP from `X-Forwarded-For` (it is trusted *only* from those peers,
since the header is otherwise spoofable). The per-account login lockout is the
primary brute-force defense and works regardless.

Build a static binary: `cd backend && go build -o passwd-server ./cmd/server`
(pure-Go SQLite, no cgo). Back up the DB file; it holds only ciphertext and
verifiers. TOTP secrets are additionally encrypted at rest (AES-256-GCM under a key
derived from `PASSWD_IDENTIFIER_PEPPER`), so a stolen DB or backup alone — without
that secret — cannot read enrolled second-factor secrets.

### Storage backend (SQLite or PostgreSQL)

`PASSWD_DB` selects the backend: a filesystem path uses **SQLite** (the simple
single-binary default); a `postgres://user:pass@host:5432/passwd?sslmode=require`
URL uses **PostgreSQL** (for larger / multi-tenant deployments). Both implement the
same `storage.Store` interface and pass the same contract tests; the schema is
created automatically on first boot. Use `sslmode=require` (or stricter) for any
non-local Postgres.

### Docker (compose)

`backend/Dockerfile` builds a tiny static image, and the root `docker-compose.yml`
runs it with a persistent volume:

```bash
cp .env.example .env          # set PASSWD_JWT_SECRET, PASSWD_IDENTIFIER_PEPPER, origins
docker compose up -d --build  # backend on :8080, DB in the passwd-data volume
```

The image runs as a non-root user (uid 10001) and stores the DB at
`/data/passwd.db`. A fresh named volume inherits that ownership; if you bind-mount
a host path instead, `chown 10001:10001` it first. Still terminate TLS in front of
the container.

### Secrets management

There are two secrets that matter: `PASSWD_JWT_SECRET` and
`PASSWD_IDENTIFIER_PEPPER`. Generate each as a long random value:

```bash
openssl rand -hex 32
```

Provide them by whichever fits your platform — the server checks them in this
order:

1. **`<NAME>_FILE`** (preferred for prod): a path to a file containing the secret.
   This is how Docker/Kubernetes secrets are mounted, so the value never sits in
   the environment or the compose file. Example:
   `PASSWD_JWT_SECRET_FILE=/run/secrets/jwt_secret`.
2. **`<NAME>`**: the secret directly in the environment.
3. Built-in dev default — **rejected at startup when `PASSWD_ENV=production`.**

Docker secrets with compose:

```yaml
services:
  backend:
    environment:
      PASSWD_JWT_SECRET_FILE: /run/secrets/jwt_secret
      PASSWD_IDENTIFIER_PEPPER_FILE: /run/secrets/identifier_pepper
    secrets: [jwt_secret, identifier_pepper]
secrets:
  jwt_secret:
    file: ./secrets/jwt_secret.txt
  identifier_pepper:
    file: ./secrets/identifier_pepper.txt
```

For the simpler `.env` flow, keep `.env` out of git (it already is) and
`chmod 600` it.

**Rotation:**
- `PASSWD_JWT_SECRET` — safe to rotate. Outstanding access tokens stop verifying,
  but clients transparently mint new ones via their (separately stored) refresh
  tokens; worst case a user signs in again. No data loss.
- `PASSWD_IDENTIFIER_PEPPER` — **never rotate after launch.** It is mixed into the
  HMAC that blinds every account identifier; changing it makes all existing
  accounts unfindable (effectively orphaned). Treat it as permanent and back it up.

Back up the DB file regularly — it holds only ciphertext and password verifiers,
never plaintext or master passwords.

## Web vault (production)

`cd clients && npm -w @passwd/web run build` → static files in
`apps/web/dist`. Host them on any static host/CDN. The API base is set at build
time via `VITE_API_BASE` (see `apps/web/.env.example`):
- **Same-origin (simplest):** leave `VITE_API_BASE` empty and reverse-proxy
  `/api` → backend on the same host as the SPA; no CORS needed.
- **Separate origin:** set `VITE_API_BASE=https://api.example.com` and add the SPA
  origin to the backend's `PASSWD_ALLOWED_ORIGINS`.

## Marketing site (production)

`cd site && npm run build` → static files in `site/dist`. The "Open vault" /
"Create free vault" buttons and repo links are set at build time via
`PUBLIC_VAULT_URL` and `PUBLIC_GITHUB_URL` (see `site/.env.example`). The
desktop **Download** button points at `PUBLIC_RELEASES_URL` (defaults to
`$PUBLIC_GITHUB_URL/releases/latest`), i.e. the releases produced below.

## Releasing the desktop app

The standalone Tauri vault (`clients/apps/desktop`) is built and published by
`.github/workflows/desktop-release.yml`. It runs a matrix on Linux, macOS
(Apple silicon + Intel) and Windows, then attaches the bundles to a GitHub
Release.

- **Cut a release:** bump the version in `clients/apps/desktop/src-tauri/tauri.conf.json`
  (and `package.json`), then push a tag `vX.Y.Z`. The workflow creates a draft
  release `passwd vX.Y.Z` with the per-platform assets (Linux AppImage/.deb,
  macOS `.dmg`, Windows `.msi`/NSIS). Review and publish it.
- **Dry run:** trigger the workflow manually (`workflow_dispatch`) to build a
  draft release for the current version without tagging.

### Signing (set as repo secrets when available)

Builds are **unsigned** until these are present; the workflow picks them up
automatically once set.

- **macOS notarization:** `APPLE_CERTIFICATE`, `APPLE_CERTIFICATE_PASSWORD`,
  `APPLE_SIGNING_IDENTITY`, `APPLE_ID`, `APPLE_PASSWORD`, `APPLE_TEAM_ID`
  (Developer ID Application cert + an app-specific password / API key).
- **Windows code signing:** provide a code-signing certificate and configure
  `bundle.windows` in `tauri.conf.json` (e.g. `signCommand` / Azure Trusted
  Signing) so `signtool` runs during the bundle step.

## Publishing the browser extension

Build distributable zips (WXT):

```bash
cd clients
npm -w @passwd/extension run zip          # -> .output/<name>-<ver>-chrome.zip
npm -w @passwd/extension run zip:firefox  # -> .output/<name>-<ver>-firefox.zip (+ sources zip)
```

Before publishing: set a **real, permanent** Gecko id in `wxt.config.ts`
(`browser_specific_settings.gecko.id`, e.g. `passwd@yourdomain.com`) and build with
your production URLs exported, so the inlined API base *and* the manifest
`host_permissions` both point at the real API domain (see
`apps/extension/.env.example`):

```bash
WXT_API_BASE=https://api.example.com WXT_VAULT_URL=https://vault.example.com \
  npm -w @passwd/extension run zip
```

### Firefox — addons.mozilla.org (AMO)

1. Create a Firefox account and sign in to <https://addons.mozilla.org/developers/>.
2. **Submit a New Add-on** → upload the `*-firefox.zip`. Because the source is
   bundled/minified, also upload the **sources zip** WXT generates (AMO requires
   reviewable source for bundled add-ons).
3. Choose distribution:
   - **On this site (listed):** AMO reviews + signs, and it's listed on
     addons.mozilla.org for anyone to install.
   - **On your own (self-distribution):** AMO signs and returns a signed `.xpi`
     you host yourself; users install it directly.
4. Fill in listing metadata (description, icons, screenshots, privacy policy —
   emphasize zero-knowledge) and submit. Review can take from minutes to days.
5. CI alternative: `web-ext sign` (web-ext ships with WXT) using an AMO API
   key/secret from the Developer Hub to sign without the web UI.

Notes: an **unsigned** add-on can only be loaded temporarily (`about:debugging`)
or in Firefox Developer/Nightly editions; release Firefox requires a signed,
AMO-issued build. We build Firefox as MV2 today (`.output/firefox-mv2`); Firefox
MV3 is an option later.

### Chrome — Chrome Web Store

1. Register at the [Chrome Web Store Developer Dashboard](https://chrome.google.com/webstore/devconsole)
   (one-time US$5 fee).
2. **Add new item** → upload the `*-chrome.zip` (MV3).
3. Fill in listing + privacy disclosures and submit for review.

(Edge uses the same MV3 zip via Partner Center; Safari needs a separate
`safari-web-extension-converter` step — out of scope for now.)
