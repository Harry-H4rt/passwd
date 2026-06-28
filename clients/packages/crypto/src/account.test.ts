import { test } from "node:test";
import assert from "node:assert/strict";
import { buildRegistration, unlock, encryptItem, decryptItem } from "./account.js";
import type { KdfParams } from "./kdf.js";

// Use pbkdf2 so tests run without the hash-wasm (argon2) native dependency.
// A separate, slower suite should cover the argon2id default path.
const KDF: KdfParams = { type: "pbkdf2", iterations: 100_000 };

const EMAIL = "Alice@Example.com";
const PASSWORD = "correct horse battery staple";

test("register → unlock recovers the user key and auth hash", async () => {
  const { bundle, userKey } = await buildRegistration(EMAIL, PASSWORD, KDF);
  const session = await unlock(EMAIL, PASSWORD, KDF, bundle.protectedUserKey);
  assert.deepEqual(session.userKey, userKey);
  assert.equal(session.masterPasswordHash, bundle.masterPasswordHash);
  assert.equal(bundle.email, "alice@example.com"); // normalized
});

test("vault item round-trips through encrypt/decrypt", async () => {
  const { userKey } = await buildRegistration(EMAIL, PASSWORD, KDF);
  const secret = JSON.stringify({ site: "github.com", password: "hunter2" });
  const cipher = await encryptItem(userKey, secret);
  assert.ok(cipher.startsWith("1.")); // AES-GCM EncString
  assert.equal(await decryptItem(userKey, cipher), secret);
});

test("email salt is case- and whitespace-insensitive", async () => {
  const { bundle, userKey } = await buildRegistration(EMAIL, PASSWORD, KDF);
  const cipher = await encryptItem(userKey, "secret");
  const session = await unlock("  alice@EXAMPLE.com  ", PASSWORD, KDF, bundle.protectedUserKey);
  assert.equal(await decryptItem(session.userKey, cipher), "secret");
});

test("wrong password cannot unwrap the user key", async () => {
  const { bundle } = await buildRegistration(EMAIL, PASSWORD, KDF);
  await assert.rejects(unlock(EMAIL, "wrong password", KDF, bundle.protectedUserKey));
});

test("tampered ciphertext is rejected by the AEAD tag", async () => {
  const { userKey } = await buildRegistration(EMAIL, PASSWORD, KDF);
  const cipher = await encryptItem(userKey, "secret");
  const tampered = cipher.slice(0, -2) + (cipher.endsWith("=") ? "A=" : "AA");
  await assert.rejects(decryptItem(userKey, tampered));
});
