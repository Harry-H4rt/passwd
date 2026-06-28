import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { deriveKey } from "./kdf.js";
import { hkdfExpand, aesGcmEncrypt, utf8 } from "./primitives.js";
import { deriveMasterPasswordHash } from "./account.js";
import { serializeEncString, EncType } from "./encstring.js";
import { normalizeIdentifier } from "./identifier.js";

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  readFileSync(resolve(here, "../../../../docs/test-vectors.json"), "utf8"),
);
const { inputs, expected } = vectors;

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const unhex = (s: string) => new Uint8Array(Buffer.from(s, "hex"));

// This suite guarantees the TS package still matches the committed vectors that
// the Go reference impl is also held to — so client and server can never silently
// disagree on the crypto.

test("KDF: pbkdf2 master key matches vector", async () => {
  const mk = await deriveKey(inputs.password, normalizeIdentifier(inputs.identifier), inputs.pbkdf2);
  assert.equal(hex(mk), expected.masterKeyPbkdf2Hex);
});

test("KDF: argon2id master key matches vector", async () => {
  const mk = await deriveKey(inputs.password, normalizeIdentifier(inputs.identifier), inputs.argon2id);
  assert.equal(hex(mk), expected.masterKeyArgon2idHex);
});

test("HKDF-Expand enc/mac subkeys match vector", async () => {
  const mk = unhex(expected.masterKeyPbkdf2Hex);
  assert.equal(hex(await hkdfExpand(mk, inputs.hkdfInfoEnc, 32)), expected.stretchedEncKeyHex);
  assert.equal(hex(await hkdfExpand(mk, inputs.hkdfInfoMac, 32)), expected.stretchedMacKeyHex);
});

test("master password hash matches vector", async () => {
  const mk = unhex(expected.masterKeyPbkdf2Hex);
  assert.equal(await deriveMasterPasswordHash(mk, inputs.password), expected.masterPasswordHashB64);
});

test("AES-256-GCM ciphertext matches vector", async () => {
  const { ciphertext } = await aesGcmEncrypt(unhex(inputs.aesKeyHex), utf8(inputs.aesPlaintext), unhex(inputs.aesNonceHex));
  assert.equal(hex(ciphertext), expected.aesGcmCiphertextHex);
});

test("EncString serialization matches vector", () => {
  const s = serializeEncString({
    type: EncType.AesGcm,
    nonce: unhex(inputs.aesNonceHex),
    data: unhex(expected.aesGcmCiphertextHex),
  });
  assert.equal(s, expected.encString);
});
