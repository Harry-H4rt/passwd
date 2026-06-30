# Internal security review

This records an internal code-and-design security review of passwd and the
remediations applied. It is **not** the independent third-party cryptographic and
application audit required before storing real user data (the Phase 5 roadmap
gate) — that must come from an external firm. This document is intended to give
that firm a head start.

**Scope:** `@passwd/crypto`, the Go backend (`auth`, `server`, `storage`,
`config`, `cmd/server`), and the offline backup/vault encryption.

## Findings and resolutions

| # | Severity | Finding | Resolution |
|---|----------|---------|------------|
| 1 | Medium | Account **enumeration via timing**: Argon2id ran only for existing accounts on login and recovery. | Added `auth.DummyVerify`, run against a decoy verifier for unknown accounts on login, passkey login, and recovery, so timing no longer reveals existence. |
| 2 | Medium | Master-password rotation via recovery **left existing sessions valid**. | `handleRecoveryComplete` now calls `DeleteRefreshTokensForUser`, revoking all sessions on reset. |
| 3 | Medium | IP rate limiter used `RemoteAddr`, so it **collapsed to one bucket behind a reverse proxy**. | Added `PASSWD_TRUSTED_PROXIES`; `X-Forwarded-For` is honored only from configured trusted proxies. The per-account lockout remains the primary brute-force defense. |
| 4 | Medium | Weak master-password policy (8-char min) → **offline brute force** of `.passwd` files / backups. | Added `masterPasswordIssue` in `@passwd/crypto` (12-char minimum, favors passphrases); enforced in the web register/recovery flows and the desktop create/change-password flows. |
| 5 | Low/Med | TOTP codes were **replayable** within their validity window. | Login now records the consumed TOTP time-step (`TOTPLastCounter`) and rejects any code whose step is not strictly newer. |
| 6 | Low/Med | `masterPasswordHash` lacked a **domain-separation** string. | Frozen: salt is now `passwd.master-password-hash.v1:` + password, in both the TS and Go implementations, with an updated cross-checked test vector. |
| 7 | Low | Recovery **bypasses 2FA** and enrollment is silent. | By design (escape hatch); mitigated by the session revocation in #2 and the one-time UI warning. Documented in `CRYPTO.md`. |
| 8 | Low | No refresh-token **reuse detection**. | Rotated tokens are retained as `used`; presenting a used token is treated as theft and revokes the user's whole session family. |
| 9 | Low | TOTP secret stored **plaintext at rest**. | Encrypted at rest with AES-256-GCM under a key derived from `PASSWD_IDENTIFIER_PEPPER` (`auth.SecretBox*`). |
| 10 | Info | In-memory lockout/rate-limit not shared across instances; no audit log. | Acknowledged. These are deployment/feature concerns for the multi-tenant phase (a shared store and an audit log), not single-binary code defects; tracked in the roadmap. |

## Confirmed strengths

- Authentication is cleanly separated from encryption; the server stores only
  ciphertext, an Argon2id verifier, and a blinded identifier.
- JWT verification is not vulnerable to algorithm confusion (HS256 is always
  recomputed and compared in constant time; the header `alg` is never trusted).
- Constant-time comparisons for the verifier, TOTP, and JWT signature; refresh
  tokens are stored only as SHA-256 and rotated on use.
- Vault CRUD is owner-scoped in storage (`WHERE id = ? AND user_id = ?`); no IDOR.
- Locked-down JSON-API security headers and CSP; credential-less CORS limited to
  allowlisted and browser-extension origins.
- The recovery design preserves zero-knowledge: the recovery code independently
  wraps the same User Key, the server verifies a recovery hash without learning the
  code, and the challenge returns a shaped decoy to avoid a recovery-enabled oracle.

## Still required before launch

- An **independent** third-party crypto + application audit (the roadmap gate).
- Decide single User Key vs. per-item keys (open design question).
