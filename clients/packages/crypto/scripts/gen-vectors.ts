// Regenerates docs/test-vectors.json from the real @passwd/crypto implementation.
// These known-answer vectors are the contract the Go reference impl must also
// satisfy, guaranteeing client (TS) and server (Go) crypto never diverge.
//
//   npm -w @passwd/crypto run gen-vectors
//
// All inputs are fixed and all operations deterministic (explicit nonces), so the
// output is stable across runs and languages.

import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { writeFileSync } from "node:fs";

import { deriveKey, type KdfParams } from "../src/kdf.js";
import { hkdfExpand, aesGcmEncrypt, utf8 } from "../src/primitives.js";
import { deriveMasterPasswordHash } from "../src/account.js";
import { serializeEncString, EncType } from "../src/encstring.js";
import { normalizeIdentifier } from "../src/identifier.js";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const unhex = (s: string) => new Uint8Array(Buffer.from(s, "hex"));

const PASSWORD = "correct horse battery staple";
const IDENTIFIER = "alice@example.com";

const PBKDF2: KdfParams = { type: "pbkdf2", iterations: 100_000 };
// Light argon2id params keep the test fast while still exercising the real KDF.
const ARGON2: KdfParams = { type: "argon2id", iterations: 2, memoryMiB: 8, parallelism: 1 };

// Fixed key/nonce/plaintext for the deterministic AES-GCM vector.
const AES_KEY = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
const AES_NONCE = unhex("0102030405060708090a0b0c");
const AES_PLAINTEXT = "vault item: github.com / alice / hunter2";

async function main() {
  const salt = normalizeIdentifier(IDENTIFIER);

  const masterKeyPbkdf2 = await deriveKey(PASSWORD, salt, PBKDF2);
  const masterKeyArgon2 = await deriveKey(PASSWORD, salt, ARGON2);

  const encKey = await hkdfExpand(masterKeyPbkdf2, "enc", 32);
  const macKey = await hkdfExpand(masterKeyPbkdf2, "mac", 32);

  const mph = await deriveMasterPasswordHash(masterKeyPbkdf2, PASSWORD);

  const gcm = await aesGcmEncrypt(AES_KEY, utf8(AES_PLAINTEXT), AES_NONCE);
  const encString = serializeEncString({ type: EncType.AesGcm, nonce: AES_NONCE, data: gcm.ciphertext });

  const vectors = {
    _comment:
      "Known-answer vectors for @passwd/crypto. Both the TS package and the Go " +
      "reference impl must reproduce these exactly. Regenerate via " +
      "`npm -w @passwd/crypto run gen-vectors`.",
    inputs: {
      password: PASSWORD,
      identifier: IDENTIFIER,
      normalizedIdentifier: salt,
      pbkdf2: PBKDF2,
      argon2id: ARGON2,
      aesKeyHex: hex(AES_KEY),
      aesNonceHex: hex(AES_NONCE),
      aesPlaintext: AES_PLAINTEXT,
      hkdfInfoEnc: "enc",
      hkdfInfoMac: "mac",
    },
    expected: {
      masterKeyPbkdf2Hex: hex(masterKeyPbkdf2),
      masterKeyArgon2idHex: hex(masterKeyArgon2),
      stretchedEncKeyHex: hex(encKey),
      stretchedMacKeyHex: hex(macKey),
      masterPasswordHashB64: mph,
      aesGcmCiphertextHex: hex(gcm.ciphertext),
      encString,
    },
  };

  const here = dirname(fileURLToPath(import.meta.url));
  const repoRoot = resolve(here, "../../../.."); // scripts -> crypto -> packages -> clients -> root
  const outPath = resolve(repoRoot, "docs/test-vectors.json");
  writeFileSync(outPath, JSON.stringify(vectors, null, 2) + "\n");
  console.log("wrote", outPath);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
