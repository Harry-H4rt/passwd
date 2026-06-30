# Cryptographic design

This is the most important document in the repo. The whole product's trust model
rests on it. It mirrors the [Bitwarden security whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/)
with the modernizations noted below.

## Goals

1. **Zero-knowledge:** the server stores only ciphertext + a salted password
   verifier. A full server/database compromise must not reveal vault contents or
   the master password.
2. **Separation of authentication from encryption:** the value used to log in is
   *not* the value used to decrypt the vault. Neither the master password nor the
   master key is ever sent to the server.
3. **Crypto-agility:** every stored blob is tagged with the KDF + cipher
   parameters used, so we can rotate algorithms without breaking old accounts.

## Primitives

| Purpose | Algorithm | Notes |
|---|---|---|
| Key derivation (KDF) | **Argon2id** (default) | `m=64 MiB, t=3, p=4`. PBKDF2-HMAC-SHA256 (≥600k) supported for compatibility/fallback. |
| Key stretching | **HKDF-SHA256** | expands the 256-bit master key → 512-bit stretched key |
| Item / key encryption | **AES-256-GCM** (AEAD) | 96-bit random nonce per encryption; never reuse a nonce under a key |
| Random generation | CSPRNG | `crypto.getRandomValues` (web) / `crypto/rand` (Go) |
| Server-side verifier storage | **Argon2id** over the auth hash | so a DB leak still can't be used to log in |

> **Why we diverge from Bitwarden's defaults:** Bitwarden defaults to PBKDF2 and
> uses AES-CBC + HMAC for legacy/compat reasons. A greenfield product has no
> legacy users, so we default to Argon2id (OWASP-recommended) and AES-GCM (an
> AEAD — authentication is built in, removing a class of encrypt-then-MAC
> mistakes). See Palant's analysis of Bitwarden's server-side-iteration history
> for why getting KDF handling right matters: https://palant.info/2023/01/23/bitwarden-design-flaw-server-side-iterations/

## Key hierarchy

All of this happens **client-side** (in the web vault and the extension, via the
shared `@passwd/crypto` package). The server never sees anything above the dashed line.

```
                       master password (user input)
                                  │
          ┌───────────────────────┴────────────────────────┐
          │  KDF(password, salt = lowercase(email), params) │   Argon2id
          └───────────────────────┬────────────────────────┘
                                  ▼
                         Master Key (256-bit)  ──────────────┐  never leaves device
                                  │                           │
        ┌─────────────────────────┴──────────┐               │
        ▼                                      ▼              ▼
 HKDF-Expand("enc")                    KDF(masterKey, 1)   used to wrap the
        │                              = Master Password   User Key
        ▼                                  Hash (auth)         │
 Stretched Master Key (512-bit)             │                  │
   = encKey(256) ‖ macKey(256)              │                  │
        │                                    │                  │
        │   AES-GCM-unwrap                   │                  │
        ▼                                    │                  │
 ┌──────────────┐                            │                  │
 │  User Key    │  (512-bit, CSPRNG)         │                  │
 │ (Symmetric)  │◀───────────────────────────┼──────────────────┘
 └──────┬───────┘                            │
        │ encrypts every vault item          │
        ▼                                    ▼
   vault item ciphertext            ── send to server ──▶  Master Password Hash
   (AES-256-GCM)                                            (login credential)
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
SERVER STORES: Protected (wrapped) User Key, all item ciphertext,
               Argon2id(Master Password Hash) + salt, KDF params.
```

### Step by step

1. **Master Key** = `Argon2id(masterPassword, salt=lowercase(email), m,t,p)` → 256 bits.
   Email-as-salt makes the derivation account-specific without a server round-trip.
2. **Master Password Hash** (the *auth* credential) = one additional KDF pass over
   the Master Key with the master password as salt (a domain-separated value).
   This is sent to the server at login. The server then stores
   `Argon2id(masterPasswordHash, random salt)` — it never persists the value the
   client sends.
3. **Stretched Master Key** = `HKDF-Expand(masterKey, info="enc", 64 bytes)` →
   split into a 256-bit encryption key and 256-bit MAC key (the MAC half is
   reserved for the optional AES-CBC+HMAC compatibility cipher; AES-GCM uses only
   the encryption half).
4. **User Key** = 512 bits from CSPRNG, generated once at signup. It is wrapped
   (encrypted) with the Stretched Master Key and the result — the **Protected
   User Key** — is uploaded. On every login the client downloads it and unwraps
   it locally.
5. **Vault items** are each encrypted with the User Key using AES-256-GCM. (A
   future enhancement, matching Bitwarden, is a per-item key wrapped by the User
   Key; tracked in the roadmap.)

### Encrypted blob format (`EncString`)

Every ciphertext is serialized as a self-describing string so we stay crypto-agile:

```
<type>.<base64(nonce)>|<base64(ciphertext+tag)>
```

`type` is an integer enum: `1` = AES-256-GCM, `2` = AES-256-CBC-HMAC-SHA256
(compat). Parsers must reject unknown types.

## Account identity (blinding) — ultra-privacy

The account's login handle (the **identifier**) is either a generated BIP39
passphrase (privacy-first default) or an email (opt-in convenience). The crypto
layer is identifier-agnostic: the normalized identifier is the KDF salt.

The server **never stores the plaintext identifier**. It stores only a blinded
hash:

```
identifierHash = HMAC-SHA256(serverPepper, normalize(identifier))
```

- `serverPepper` is a server-side secret (`PASSWD_IDENTIFIER_PEPPER`). It must be
  strong and **stable** — rotating it orphans every account.
- Blinding means a stolen database cannot enumerate users, and (without the
  pepper) cannot even confirm a guessed identifier. Email accounts are blinded
  too, so choosing email costs nothing in privacy — but the server then has no
  way to contact users (no notifications, no email-based reset).
- `normalize` = trim + lowercase + collapse internal whitespace (shared by TS and
  Go; see test vectors).

**Stored per user:** `{ identifierHash, kdfParams, argon2id(masterPasswordHash),
protectedUserKey }`. **Ciphers are fully opaque** — id, owner, EncString blob, and
timestamps only. No item type, no name, no URL, no password hint. No PII in logs;
rate-limit/lockout state is ephemeral and in-memory.

## What the server can and cannot do

| The server CAN | The server CANNOT |
|---|---|
| Verify login (compare Argon2id verifier) | Learn the master password |
| Store & return encrypted blobs | Decrypt any vault item |
| Enforce 2FA, rate limits, account lockout | Recover a forgotten master password |
| Rotate which ciphertexts it holds | Read item names, URLs, notes, or passwords |
| (nothing) | Learn the plaintext identifier / who its users are |
| (nothing) | See even the *type* of a stored item |

**Consequence:** a forgotten master password = unrecoverable vault *unless* the
user opted into a recovery code (below). There is never a server-side reset.

## Account recovery (recovery code)

A **recovery code** is an optional, user-controlled way back into the vault after
a forgotten master password. It never lets the server reset anything.

It is a 24-word BIP39 phrase generated on the device (≈264 bits). It does **not**
re-encrypt the vault: instead it independently wraps the *same* User Key, so
recovery leaves every stored cipher valid.

```
recovery code (24 words, shown once)
        │  PBKDF2(normalize(phrase), "passwd.recovery.salt.v1")
        ▼
  recovery base key
        │
   ┌────┴───────────────┐
   ▼                     ▼
HKDF "recovery-enc"   HKDF "recovery-auth"
   │                     │
   ▼                     ▼
recoveryEncKey       recoveryAuthHash ── server stores Argon2id(this) as a verifier
   │
   │ AES-GCM-wrap the User Key
   ▼
Recovery-Protected User Key ── uploaded
```

- **Enroll** (while unlocked): wrap the in-memory User Key with `recoveryEncKey`
  and upload `{ recoveryProtectedUserKey, recoveryAuthHash }`. The server stores
  the wrapped key and `Argon2id(recoveryAuthHash)` — never the phrase or the code.
- **Recover:** the client fetches the recovery-wrapped key (`/api/auth/recovery/
  challenge`), unwraps the User Key with the phrase, the user picks a **new**
  master password, and the client re-wraps the *same* User Key under it. The
  server authorizes the swap by verifying `recoveryAuthHash` against the stored
  verifier (`/api/auth/recovery/complete`), exactly like a login.
- **No oracle:** the challenge returns a random, correctly-shaped decoy blob for
  unknown identifiers / accounts without recovery, so it doesn't reveal whether an
  account exists or has recovery enabled. The complete step shares the per-account
  lockout with login.
- **Session revocation:** completing recovery revokes every existing refresh token
  for the account, so a session stolen before the reset cannot outlive it.
- **Tradeoff:** the recovery code is an account-level escape hatch that bypasses
  any TOTP/passkey second factor, so it must be guarded as carefully as the master
  password. The UI shows it exactly once and warns accordingly.

Delegated **emergency access** (granting a trusted contact time-delayed access via
per-recipient public-key crypto) is future work, tracked in the roadmap.

## Threat model (summary)

- **In scope:** server compromise, database exfiltration, network MITM, malicious
  server operator, stolen at-rest backups.
- **Partially mitigated:** compromised client device (mitigate with auto-lock,
  memory hygiene), phishing (mitigate with extension domain-matching for
  autofill), offline brute force of a stolen backup or `.passwd` desktop vault
  (mitigate with Argon2id and a minimum master-password policy enforced by every
  client — see `@passwd/crypto` `masterPasswordIssue`).
- **Out of scope (for now):** a fully compromised browser/OS with a keylogger.

## Open decisions / TODO before any audit

- [x] Known-answer test vectors for every primitive, cross-checked TS↔Go
      (`docs/test-vectors.json`).
- [x] "Master Password Hash" derivation frozen: 1 PBKDF2 pass over the master key,
      salted by a domain-separated value (`passwd.master-password-hash.v1:` +
      password). Cross-checked TS↔Go against `docs/test-vectors.json`.
- [ ] Decide per-item keys vs. single User Key (Bitwarden uses per-item).
- [ ] Account/key rotation flow (re-encrypt-all on password change).
- [x] 2FA: TOTP implemented (server-verified). Note: the TOTP secret is held
      server-side because the server must verify codes — it is an *auth factor*,
      not vault data, and never touches vault contents. WebAuthn/passkeys next.
- [x] User-controlled recovery code (recovery phrase independently wraps the User
      Key; server verifies a recovery hash to authorize a password reset, never a
      server-side reset). Delegated emergency access is still future work.
- [ ] Independent crypto review **before** storing any real user data.
