# Roadmap

A staged plan from skeleton → real product. Each phase should end with something
runnable and tested. **Security review gates ship before real user data.**

## Phase 0 — Foundations ✅ (scaffolded)

- [x] Monorepo layout + docs (ARCHITECTURE, CRYPTO, ROADMAP)
- [x] Go backend that compiles & runs (`/healthz`, route stubs, in-memory store)
- [x] `@passwd/crypto` package: key hierarchy implemented in TypeScript
- [ ] `@passwd/api-client` typed client
- [ ] CI (build + test Go and TS)

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

## Phase 3 — Web vault

- [ ] Vite + React app: register, unlock, vault list, item CRUD
- [ ] Auto-lock / clear keys from memory on lock
- [ ] Password generator
- [ ] Import/export (encrypted + plaintext-with-warning)

## Phase 4 — Browser extension (MV3, WXT)

- [ ] Reuse `@passwd/crypto` + `@passwd/api-client`
- [ ] Popup vault, unlock, search
- [ ] Autofill with **domain matching** (anti-phishing)
- [ ] Save-on-submit detection
- [ ] Chrome + Firefox builds

## Phase 5 — Hardening & 2FA

- [ ] TOTP, then WebAuthn/passkeys
- [ ] CSP, security headers, secrets management
- [ ] Emergency access / recovery codes (user-controlled, never server reset)
- [ ] **Independent crypto + app security audit**

## Phase 6 — Site & distribution

- [ ] Astro marketing/download site
- [ ] Extension store submissions (Chrome Web Store, AMO)
- [ ] Signed release binaries + self-host docs (Docker)

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
