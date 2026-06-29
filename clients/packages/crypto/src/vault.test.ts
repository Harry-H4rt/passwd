import { test } from "node:test";
import assert from "node:assert/strict";
import {
  createVault,
  openVault,
  saveVault,
  changeMasterPassword,
  isVaultFile,
  VAULT_FORMAT,
} from "./vault.js";

// Cheap KDF params so the tests stay fast.
const fastKdf = { type: "argon2id", iterations: 1, memoryMiB: 8, parallelism: 1 } as const;

const payload = (items: unknown) => JSON.stringify({ items });

test("create -> open round-trips the payload under the right password", async () => {
  const data = payload([{ name: "GitHub", username: "me", password: "hunter2" }]);
  const { file } = await createVault("correct horse", data, fastKdf);
  const { payload: out } = await openVault(file, "correct horse");
  assert.equal(out, data);
});

test("the file hides the payload and is self-describing", async () => {
  const { file } = await createVault("pw", payload([{ password: "topsecret-value" }]), fastKdf);
  const parsed = JSON.parse(file);
  assert.equal(parsed.format, VAULT_FORMAT);
  assert.ok(parsed.salt && parsed.protectedUserKey && parsed.vault);
  assert.ok(!file.includes("topsecret-value"));
  assert.ok(isVaultFile(file));
  // No plaintext verifier / master-password hash is stored.
  assert.ok(!("masterPasswordHash" in parsed) && !("verifier" in parsed));
});

test("wrong master password is rejected", async () => {
  const { file } = await createVault("right", payload([]), fastKdf);
  await assert.rejects(() => openVault(file, "wrong"), /wrong master password or corrupted/);
});

test("save re-encrypts a new payload without changing the key wrapping", async () => {
  const { file, state } = await createVault("pw", payload([]), fastKdf);
  const before = JSON.parse(file);

  const updated = payload([{ name: "Email", password: "s3cr3t" }]);
  const file2 = await saveVault(state, updated);
  const after = JSON.parse(file2);

  // Same wrapped key + salt (no re-key), but a fresh payload ciphertext.
  assert.equal(after.protectedUserKey, before.protectedUserKey);
  assert.equal(after.salt, before.salt);
  assert.notEqual(after.vault, before.vault);
  assert.ok(!file2.includes("s3cr3t"));

  const { payload: out } = await openVault(file2, "pw");
  assert.equal(out, updated);
});

test("changing the master password re-keys but preserves the payload", async () => {
  const data = payload([{ name: "Bank", password: "vault-data" }]);
  const { state } = await createVault("old-pw", data, fastKdf);
  const { file: rekeyed } = await changeMasterPassword(state, "new-pw", data, fastKdf);

  // New password opens it; old password no longer works.
  const { payload: out } = await openVault(rekeyed, "new-pw");
  assert.equal(out, data);
  await assert.rejects(() => openVault(rekeyed, "old-pw"), /wrong master password or corrupted/);
});

test("a tampered ciphertext fails authentication", async () => {
  const { file } = await createVault("pw", payload([{ password: "x" }]), fastKdf);
  const obj = JSON.parse(file);
  // Corrupt one base64 char in the middle of the ciphertext (the data half of the
  // "<type>.<nonce>|<data>" EncString), so a content/tag byte definitely changes.
  const v: string = obj.vault;
  const mid = Math.floor((v.indexOf("|") + 1 + v.length) / 2);
  obj.vault = v.slice(0, mid) + (v[mid] === "A" ? "B" : "A") + v.slice(mid + 1);
  await assert.rejects(() => openVault(JSON.stringify(obj), "pw"), /wrong master password or corrupted/);
});

test("non-vault input is rejected without prompting", async () => {
  assert.equal(isVaultFile("not json"), false);
  assert.equal(isVaultFile('{"format":"passwd-backup"}'), false);
  await assert.rejects(() => openVault("not json", "pw"), /not a valid passwd vault/);
  await assert.rejects(() => openVault('{"format":"x"}', "pw"), /not a passwd vault file/);
});

test("empty master password is refused", async () => {
  await assert.rejects(() => createVault("", payload([]), fastKdf), /master password is required/);
});
