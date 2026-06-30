import { test } from "node:test";
import assert from "node:assert/strict";
import { buildRegistration } from "./account.js";
import { generateUserKeypair, createShare, openShare } from "./sharing.js";
import type { KdfParams } from "./kdf.js";

const KDF: KdfParams = { type: "pbkdf2", iterations: 100_000 };

test("buildRegistration includes a sharing keypair", async () => {
  const { bundle } = await buildRegistration("alice@example.com", "correct horse battery staple", KDF);
  assert.ok(bundle.publicKey.length > 0);
  assert.ok(bundle.protectedPrivateKey.startsWith("1.")); // AES-GCM EncString
});

test("a shared item round-trips to the recipient only", async () => {
  // Bob is the recipient; his keypair is wrapped by his User Key.
  const bob = await buildRegistration("bob@example.com", "bob master password", KDF);
  const bobKeypair = { publicKey: bob.bundle.publicKey, protectedPrivateKey: bob.bundle.protectedPrivateKey };

  const secret = JSON.stringify({ name: "shared login", password: "s3cret" });
  const envelope = await createShare(bobKeypair.publicKey, secret);

  // Bob unwraps it with his User Key + protected private key.
  const opened = await openShare(bob.userKey, bobKeypair.protectedPrivateKey, envelope);
  assert.equal(opened, secret);
});

test("a third party cannot open a share addressed to someone else", async () => {
  const bob = await buildRegistration("bob@example.com", "bob master password", KDF);
  const eve = await buildRegistration("eve@example.com", "eve master password", KDF);

  const envelope = await createShare(bob.bundle.publicKey, "for bob only");
  // Eve's private key can't unwrap a key encrypted to Bob's public key.
  await assert.rejects(openShare(eve.userKey, eve.bundle.protectedPrivateKey, envelope));
});

test("wrong User Key cannot recover the private key", async () => {
  const userKey = (await buildRegistration("c@example.com", "pw pw pw pw", KDF)).userKey;
  const kp = await generateUserKeypair(userKey);
  const envelope = await createShare(kp.publicKey, "secret");
  const otherUserKey = (await buildRegistration("d@example.com", "pw2 pw2 pw2", KDF)).userKey;
  await assert.rejects(openShare(otherUserKey, kp.protectedPrivateKey, envelope));
});
