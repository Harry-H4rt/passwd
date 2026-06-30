import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildRegistration,
  unlock,
  encryptItem,
  decryptItem,
  enrollRecovery,
  completeRecovery,
  deriveRecoveryKeys,
  encryptItemKeyed,
  decryptItemKeyed,
} from "./account.js";
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

test("per-item-keyed item round-trips and uses a fresh key each time", async () => {
  const { userKey } = await buildRegistration(EMAIL, PASSWORD, KDF);
  const secret = JSON.stringify({ site: "github.com", password: "hunter2" });

  const a = await encryptItemKeyed(userKey, secret);
  const b = await encryptItemKeyed(userKey, secret);
  // Each item is wrapped under its own random key, so identical plaintext yields
  // different containers (different wrapped key and ciphertext).
  assert.notEqual(a, b);
  assert.equal(await decryptItemKeyed(userKey, a), secret);
  assert.equal(await decryptItemKeyed(userKey, b), secret);

  const container = JSON.parse(a);
  assert.equal(container.v, 2);
  assert.ok(container.key.startsWith("1.") && container.data.startsWith("1."));
});

test("per-item: tampering with the wrapped key or data is rejected", async () => {
  const { userKey } = await buildRegistration(EMAIL, PASSWORD, KDF);
  const c = JSON.parse(await encryptItemKeyed(userKey, "secret"));
  const tamper = (s: string) => s.slice(0, -2) + (s.endsWith("=") ? "A=" : "AA");
  await assert.rejects(decryptItemKeyed(userKey, JSON.stringify({ ...c, data: tamper(c.data) })));
  await assert.rejects(decryptItemKeyed(userKey, JSON.stringify({ ...c, key: tamper(c.key) })));
});

test("decryptItemKeyed still reads a legacy single-key item", async () => {
  const { userKey } = await buildRegistration(EMAIL, PASSWORD, KDF);
  const legacy = await encryptItem(userKey, "legacy secret"); // bare EncString
  assert.equal(await decryptItemKeyed(userKey, legacy), "legacy secret");
});

test("recovery code recovers the vault under a new master password", async () => {
  const { bundle, userKey } = await buildRegistration(EMAIL, PASSWORD, KDF);
  const cipher = await encryptItem(userKey, "top secret");

  // Enroll recovery while unlocked.
  const enroll = await enrollRecovery(userKey);
  assert.equal(enroll.recoveryCode.split(" ").length, 24);
  assert.ok(enroll.recoveryProtectedUserKey.startsWith("1.")); // AES-GCM EncString

  // User forgot the master password; recover with the code + a NEW password.
  const NEW_PASSWORD = "a brand new master password";
  const reset = await completeRecovery(
    enroll.recoveryCode,
    enroll.recoveryProtectedUserKey,
    EMAIL,
    NEW_PASSWORD,
    KDF,
  );

  // The User Key is unchanged, so the old ciphertext still decrypts.
  assert.deepEqual(reset.userKey, userKey);
  assert.equal(await decryptItem(reset.userKey, cipher), "top secret");

  // The server can authorize the swap: the auth hash matches what was enrolled.
  assert.equal(reset.recoveryAuthHash, enroll.recoveryAuthHash);

  // Logging in with the new password (and the new protected key) works; the old
  // one no longer derives the User Key.
  const session = await unlock(EMAIL, NEW_PASSWORD, reset.kdf, reset.protectedUserKey);
  assert.equal(await decryptItem(session.userKey, cipher), "top secret");
  await assert.rejects(unlock(EMAIL, PASSWORD, KDF, reset.protectedUserKey));
});

test("wrong recovery code cannot unwrap the user key", async () => {
  const { userKey } = await buildRegistration(EMAIL, PASSWORD, KDF);
  const enroll = await enrollRecovery(userKey);
  await assert.rejects(
    completeRecovery(generateAccountId(24), enroll.recoveryProtectedUserKey, EMAIL, "new pw", KDF),
  );
});

test("recovery code re-typed with messy spacing/case still derives the same keys", async () => {
  const { userKey } = await buildRegistration(EMAIL, PASSWORD, KDF);
  const enroll = await enrollRecovery(userKey);
  const messy = `  ${enroll.recoveryCode.toUpperCase().replace(/ /g, "   ")} `;
  const keys = await deriveRecoveryKeys(messy);
  assert.equal(keys.recoveryAuthHash, enroll.recoveryAuthHash);
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
