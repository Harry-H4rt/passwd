# @passwd/crypto

The zero-knowledge crypto library shared by the web vault and the browser
extension. **The server never imports this.** It implements the key hierarchy in
[`../../../docs/CRYPTO.md`](../../../docs/CRYPTO.md).

## Public API

```ts
import {
  DEFAULT_KDF, buildRegistration, unlock, encryptItem, decryptItem,
} from "@passwd/crypto";

// Sign-up: derive keys, get what the server should store.
const { bundle, userKey } = await buildRegistration(email, masterPassword, DEFAULT_KDF);
// POST bundle -> /api/accounts/register   (server sees only ciphertext + auth hash)

// Encrypt a vault item locally before upload.
const cipher = await encryptItem(userKey, JSON.stringify(item)); // -> EncString

// Login/unlock on any device: recover the user key from email + password.
const { userKey, masterPasswordHash } = await unlock(email, masterPassword, kdf, protectedUserKey);
const item = JSON.parse(await decryptItem(userKey, cipher));
```

Lower-level building blocks (`deriveMasterKey`, `stretchMasterKey`, `wrapUserKey`,
`hkdfExpand`, `aesGcmEncrypt`, `parseEncString`, …) are also exported.

## Test / typecheck

```bash
npm install          # from clients/ (workspaces)
npm -w @passwd/crypto run test       # node:test via tsx (pbkdf2 path, offline)
npm -w @passwd/crypto run typecheck
```

The argon2id default path needs the `hash-wasm` dependency; tests use pbkdf2 so
they run without native modules.

> The algorithm was validated end-to-end (register → unlock → encrypt → decrypt,
> plus wrong-password and tamper rejection). Before any real users, Phase 1 must
> add **known-answer test vectors** cross-checked against a Go reference impl.
