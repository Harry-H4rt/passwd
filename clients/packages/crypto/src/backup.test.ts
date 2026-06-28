import { test } from "node:test";
import assert from "node:assert/strict";
import { decryptBackup, encryptBackup, isBackupEnvelope, BACKUP_FORMAT } from "./backup.js";

// Use cheap KDF params so the tests stay fast.
const fastKdf = { type: "argon2id", iterations: 1, memoryMiB: 8, parallelism: 1 } as const;

test("backup round-trips plaintext under the right passphrase", async () => {
  const secret = JSON.stringify({ items: [{ name: "GitHub", password: "hunter2" }] });
  const env = await encryptBackup(secret, "correct horse", fastKdf);
  assert.equal(await decryptBackup(env, "correct horse"), secret);
});

test("backup is self-describing and hides the plaintext", async () => {
  const env = await encryptBackup("topsecret-value", "pw", fastKdf);
  const parsed = JSON.parse(env);
  assert.equal(parsed.format, BACKUP_FORMAT);
  assert.ok(parsed.salt && parsed.nonce && parsed.data);
  assert.ok(!env.includes("topsecret-value"));
  assert.ok(isBackupEnvelope(env));
});

test("wrong passphrase fails to decrypt", async () => {
  const env = await encryptBackup("data", "right", fastKdf);
  await assert.rejects(() => decryptBackup(env, "wrong"), /wrong passphrase or corrupted/);
});

test("non-backup input is rejected", async () => {
  assert.equal(isBackupEnvelope("not json"), false);
  assert.equal(isBackupEnvelope('{"format":"something-else"}'), false);
  await assert.rejects(() => decryptBackup("not json", "pw"), /not a valid passwd backup/);
  await assert.rejects(() => decryptBackup('{"format":"x"}', "pw"), /not a passwd backup/);
});

test("empty passphrase is refused on encrypt", async () => {
  await assert.rejects(() => encryptBackup("data", "", fastKdf), /passphrase is required/);
});
