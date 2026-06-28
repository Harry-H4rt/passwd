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

## What the server can and cannot do

| The server CAN | The server CANNOT |
|---|---|
| Verify login (compare Argon2id verifier) | Learn the master password |
| Store & return encrypted blobs | Decrypt any vault item |
| Enforce 2FA, rate limits, account lockout | Recover a forgotten master password |
| Rotate which ciphertexts it holds | Read item names, URLs, notes, or passwords |

**Consequence:** a forgotten master password = unrecoverable vault. The UX must
make this explicit and offer an (optional, user-controlled) Emergency Access /
recovery-code mechanism, never a server-side reset.

## Threat model (summary)

- **In scope:** server compromise, database exfiltration, network MITM, malicious
  server operator, stolen at-rest backups.
- **Partially mitigated:** compromised client device (mitigate with auto-lock,
  memory hygiene), phishing (mitigate with extension domain-matching for
  autofill).
- **Out of scope (for now):** a fully compromised browser/OS with a keylogger.

## Open decisions / TODO before any audit

- [ ] Finalize the exact "Master Password Hash" derivation (domain separation
      string) and document the test vectors.
- [ ] Decide per-item keys vs. single User Key (Bitwarden uses per-item).
- [ ] Account/key rotation flow (re-encrypt-all on password change).
- [ ] 2FA: TOTP first, then WebAuthn.
- [ ] Independent crypto review **before** storing any real user data.
