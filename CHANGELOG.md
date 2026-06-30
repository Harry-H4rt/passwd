# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-30

First tagged release. **Pre-audit:** the cryptographic design is documented but has
not yet had an independent third-party audit — do not store irreplaceable secrets
yet.

### Added

- **Zero-knowledge backend** (Go): registration, login, and rotating refresh
  tokens; Argon2id password verifier; blinded (HMAC) account identifiers; opaque
  encrypted-cipher CRUD and `/api/sync`. Single static binary with SQLite.
- **Web vault** (Vite + React): register with a generated passphrase or email,
  unlock, vault list with search, item add/edit/delete, copy, password generator,
  encrypted backup export, and JSON/CSV import (Bitwarden/Chrome/generic).
- **Browser extension** (Manifest V3, Chrome + Firefox): unlock, vault list, copy,
  autofill with strict domain matching, save-on-submit prompts, and item editing.
- **Desktop app** (Tauri v2): a standalone, offline, KeePass-style vault stored as a
  single portable encrypted `.passwd` file — no backend, no network.
- **Two-factor authentication:** TOTP and WebAuthn/passkeys (coexisting).
- **Account recovery code:** an optional 24-word phrase that independently wraps the
  User Key, allowing a user-controlled password reset with no server-side reset.
- **Marketing site** (Astro) with a download section wired to GitHub Releases.
- **Documentation:** architecture, cryptographic design, deployment/self-hosting,
  and an internal security review.

### Security

- Encryption and decryption happen entirely on the client; the server stores only
  ciphertext, an Argon2id verifier, and a blinded identifier.
- Constant-time verifier/TOTP/JWT comparisons; refresh tokens stored hashed.
- Remediations from the internal security review (see `docs/SECURITY-REVIEW.md`):
  timing-equalized auth (no account enumeration), session revocation on recovery,
  trusted-proxy-aware rate limiting, a minimum master-password policy, TOTP replay
  protection, refresh-token reuse detection, domain-separated master-password hash,
  and TOTP secrets encrypted at rest.

[0.1.0]: https://github.com/Harry-H4rt/passwd/releases/tag/v0.1.0
