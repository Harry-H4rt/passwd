# Roadmap

A staged plan from skeleton → real product. Each phase should end with something
runnable and tested. **Security review gates ship before real user data.**

## Phase 0 — Foundations ✅ (scaffolded)

- [x] Monorepo layout + docs (ARCHITECTURE, CRYPTO, ROADMAP)
- [x] Go backend that compiles & runs (`/healthz`, route stubs, in-memory store)
- [x] `@passwd/crypto` package: key hierarchy implemented in TypeScript
- [x] `@passwd/api-client` typed client (shared by web vault + extension)
- [x] CI (build + test Go and TS) — GitHub Actions on push/PR to main

## Phase 1 — Crypto correctness ✅

- [x] **Known-answer test vectors** (`docs/test-vectors.json`) for KDF (pbkdf2 +
      argon2id), HKDF, master-password-hash, AES-GCM, EncString
- [x] Cross-checked between TS (`src/vectors.test.ts`) and a Go reference impl
      (`backend/internal/crypto`) — both reproduce the file byte-for-byte
- [x] Identifier-agnostic crypto + BIP39 `generateAccountId()`
- [x] master-password-hash derivation documented (still a Phase-1 "frozen pending
      audit" item)
- [ ] Decide single User Key vs. per-item keys (still open)

## Phase 2 — Backend MVP (single-tenant) ✅

- [x] SQLite storage (`modernc.org/sqlite`, no cgo) behind `storage.Store`
- [x] Blinded-identifier accounts (HMAC + pepper), **opaque ciphers** (no type)
- [x] Real `register` / `prelogin` / `login` (Argon2id verifier, std-lib HS256
      JWT + rotating refresh tokens)
- [x] Owner-scoped cipher CRUD + `/api/sync`
- [x] IP rate limiting + per-account login lockout
- [x] Integration test (register → login → refresh → CRUD → sync, owner isolation)
- [ ] Audit log (deferred)

## Phase 3 — Web vault ✅ (MVP)

- [x] Vite + React app: register (passphrase or email), sign in/unlock, vault
      list, item add/edit/delete, search, copy
- [x] Lock clears the in-memory user key
- [x] Password generator
- [x] One-time recovery-passphrase display on sign-up
- [x] Extracted shared `@passwd/api-client` (now used by web + extension)
- [ ] Auto-lock on idle timeout (only manual lock so far)
- [x] Import/export: encrypted backup (passphrase) + plaintext JSON/CSV with
      warning; CSV importer maps common managers (Bitwarden/Chrome/generic)

## Phase 4 — Browser extension (MV3, WXT) ✅ (MVP)

- [x] WXT MV3 extension reusing `@passwd/crypto` + `@passwd/api-client`
- [x] Popup: unlock, vault list, search, copy username/password, lock
- [x] Chrome build (`wxt build` → `.output/chrome-mv3`)
- [x] Firefox build verified (`build:firefox` → `.output/firefox-mv2`, Gecko
      add-on id set); load via `about:debugging` or `dev:firefox`
- [x] Autofill with **domain matching** (popup "Fill"; anti-phishing host match)
- [x] Persist unlocked session across popup opens (chrome.storage.session) +
      idle auto-lock
- [x] Save-on-submit detection (content capture -> background pending -> popup
      "save this login?" prompt)
- [x] Add/edit/delete items from the popup
- [x] Custom icons (deterministic monogram avatars; no remote favicon fetch)

## Phase 5 — Hardening & 2FA (in progress)

- [x] TOTP 2FA (enroll/verify), with web vault enable/disable + login prompt
- [x] WebAuthn/passkeys as a second factor (coexists with TOTP; login advertises
      available methods). Backend uses go-webauthn (pinned to the last Go 1.22
      release). Passkey *login* is web-vault-only: a passkey bound to the vault RP
      ID can't be asserted from the extension's `chrome-extension://` origin, so the
      extension uses TOTP. PRF-based passwordless unlock is still future work.
- [x] CSP, security headers (HSTS in prod), CORS allowlist; non-default secrets
      enforced in production
- [x] Idle auto-lock (web vault + extension)
- [ ] Emergency access / recovery codes (user-controlled, never server reset)
- [x] Secrets management for deploy: `*_FILE` support (Docker/K8s secrets) +
      generation/rotation docs in docs/DEPLOYMENT.md
- [ ] **Independent crypto + app security audit** (gate before real users)

## Phase 6 — Site & distribution (in progress)

- [x] Astro marketing/info site (home, features, security, FAQ + download) with a
      Proton-like design system (`site/src/styles/global.css`)
- [x] Web-vault redesign to match the new design language (orange accent, SVG
      icons, light/dark theme toggle mirroring the site)
- [~] Desktop app (Tauri v2): shipped as a **standalone, offline, KeePass-style
      vault** rather than a sync-client wrapper — no backend, no network; the vault
      is a single portable encrypted file (`clients/apps/desktop`, reusing
      `@passwd/crypto`). Linux AppImage + .deb build and run portably (e.g. from a
      USB stick). Remaining: cross-platform **signed** installers (mac notarization,
      Windows signing) + wiring the site's Download button.
- [ ] Extension store submissions (Chrome Web Store, AMO)
- [x] Self-host docs + Docker (backend Dockerfile + docker-compose); signed
      release binaries still TODO
- [x] Wire web/extension/site to a configurable production API + vault URL
      (VITE_API_BASE / WXT_API_BASE+WXT_VAULT_URL / PUBLIC_VAULT_URL)

## Phase 7 — SaaS evolution

- [ ] Postgres storage impl + migrations
- [ ] Organizations/teams + collection sharing (public-key crypto per org)
- [ ] Billing, multi-tenant isolation, admin console
- [ ] Observability (metrics, tracing), backups, DR

## Guiding rules

1. **Never** let plaintext secrets or the master password reach the server.
2. Get crypto + test vectors right before building UI on top of them.
3. Keep `storage` an interface so single-tenant → SaaS is a swap, not a rewrite.
4. No real users until Phase 5's audit gate passes.
