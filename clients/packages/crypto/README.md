# @passwd/crypto

The zero-knowledge cryptography library shared by the web vault, the browser
extension, and the desktop app. **The server never imports this package.** It
implements the key hierarchy and encrypted-blob format specified in
[`docs/CRYPTO.md`](../../../docs/CRYPTO.md).

## Public API

```ts
import {
  DEFAULT_KDF, buildRegistration, unlock, encryptItem, decryptItem,
  enrollRecovery, completeRecovery,
} from "@passwd/crypto";

// Sign-up: derive the key hierarchy and produce what the server should store.
const { bundle, userKey } = await buildRegistration(identifier, masterPassword, DEFAULT_KDF);
// POST `bundle` -> /api/accounts/register   (server sees only ciphertext + an auth hash)

// Encrypt a vault item locally before upload.
const cipher = await encryptItem(userKey, JSON.stringify(item)); // -> EncString

// Sign in / unlock on any device: recover the User Key from identifier + password.
const { userKey, masterPasswordHash } = await unlock(identifier, masterPassword, kdf, protectedUserKey);
const item = JSON.parse(await decryptItem(userKey, cipher));

// Account recovery: enroll a recovery code while unlocked, and later use it to
// reset the master password without the server being able to read anything.
const { recoveryCode, recoveryProtectedUserKey, recoveryAuthHash } = await enrollRecovery(userKey);
const reset = await completeRecovery(recoveryCode, recoveryProtectedUserKey, identifier, newPassword, kdf);
```

Lower-level building blocks are also exported, including `deriveMasterKey`,
`stretchMasterKey`, `wrapUserKey`, `deriveRecoveryKeys`, `hkdfExpand`,
`aesGcmEncrypt`, `parseEncString`, and the BIP39 helpers (`generateAccountId`).

## Test and typecheck

```bash
npm install                          # from clients/ (workspaces)
npm -w @passwd/crypto run test       # node:test via tsx
npm -w @passwd/crypto run typecheck
```

The default Argon2id path uses the `hash-wasm` dependency; the test suite exercises
the PBKDF2 path so it runs without native modules. Correctness is pinned by
known-answer test vectors (`src/vectors.test.ts` against `docs/test-vectors.json`)
that are cross-checked byte-for-byte with the Go reference implementation in
`backend/internal/crypto`.
