import { test } from "node:test";
import assert from "node:assert/strict";
import { buildRegistration, unlock, encryptItem, decryptItem } from "./account.js";
import { generateAccountId, normalizeIdentifier } from "./identifier.js";
import { BIP39_WORDLIST } from "./wordlist.js";
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
  assert.equal(bundle.identifier, "alice@example.com"); // normalized
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

test("generateAccountId produces valid, varied BIP39 passphrases", async () => {
  const wordset = new Set(BIP39_WORDLIST);
  const a = generateAccountId(12);
  const words = a.split(" ");
  assert.equal(words.length, 12);
  for (const w of words) assert.ok(wordset.has(w), `"${w}" not in wordlist`);
  assert.notEqual(generateAccountId(12), generateAccountId(12)); // randomized
});

test("a generated passphrase works as a login identifier", async () => {
  const id = generateAccountId();
  const { bundle, userKey } = await buildRegistration(id, PASSWORD, KDF);
  const cipher = await encryptItem(userKey, "secret");
  // user re-types it with messy spacing/case; normalization must still match
  const messy = `  ${id.toUpperCase().replace(/ /g, "   ")} `;
  assert.equal(normalizeIdentifier(messy), bundle.identifier);
  const session = await unlock(messy, PASSWORD, KDF, bundle.protectedUserKey);
  assert.equal(await decryptItem(session.userKey, cipher), "secret");
});
