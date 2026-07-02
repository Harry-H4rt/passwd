import { test } from "node:test";
import assert from "node:assert/strict";
import { parseVaultImport, toCSV, toPlaintextJSON, EXPORT_FORMAT } from "./portable.js";
import { blankFields, type ItemFields } from "./session.js";

// Expected import results are always full, normalized ItemFields.
const f = (partial: Partial<ItemFields>): ItemFields => ({ ...blankFields(), ...partial });

const item = f({
  name: "GitHub",
  url: "https://github.com",
  username: "octocat",
  password: "p@ss,word\n\"quoted\"",
  totp: "JBSWY3DPEHPK3PXP",
  notes: "line1\nline2",
});

test("plaintext JSON export round-trips through import", () => {
  const json = toPlaintextJSON([item]);
  assert.equal(JSON.parse(json).format, EXPORT_FORMAT);
  const back = parseVaultImport(json);
  assert.deepEqual(back, [item]);
});

test("typed items (card, note, custom fields) round-trip through JSON", () => {
  const card = f({
    type: "card",
    name: "Visa",
    card: { cardholder: "A B", number: "4111111111111111", expMonth: "12", expYear: "2030", cvv: "123" },
    fields: [{ label: "PIN", value: "9876", hidden: true }],
  });
  const note = f({ type: "note", name: "Wifi", notes: "hunter2" });
  assert.deepEqual(parseVaultImport(toPlaintextJSON([card, note])), [card, note]);
});

test("CSV export escapes commas, quotes and newlines, and round-trips", () => {
  const csv = toCSV([item]);
  const back = parseVaultImport(csv);
  assert.deepEqual(back, [item]);
});

test("imports a Bitwarden-style CSV with aliased headers, including TOTP", () => {
  const csv =
    "name,login_uri,login_username,login_password,login_totp,notes\nMail,https://mail.com,me@x.com,secret,JBSWY3DP,hello";
  assert.deepEqual(parseVaultImport(csv), [
    f({ name: "Mail", url: "https://mail.com", username: "me@x.com", password: "secret", totp: "JBSWY3DP", notes: "hello" }),
  ]);
});

test("imports a Chrome-style CSV (name,url,username,password)", () => {
  const csv = "name,url,username,password\nSite,https://s.com,user,pw";
  assert.deepEqual(parseVaultImport(csv), [
    f({ name: "Site", url: "https://s.com", username: "user", password: "pw" }),
  ]);
});

test("accepts a bare JSON array and maps title/uri aliases", () => {
  const json = JSON.stringify([{ title: "X", uri: "https://x.com", username: "u", password: "p" }]);
  assert.deepEqual(parseVaultImport(json), [
    f({ name: "X", url: "https://x.com", username: "u", password: "p" }),
  ]);
});

test("v1 exports (no type field) import as logins", () => {
  const v1 = JSON.stringify({
    format: EXPORT_FORMAT,
    version: 1,
    items: [{ name: "Old", url: "", username: "u", password: "p", notes: "" }],
  });
  assert.deepEqual(parseVaultImport(v1), [f({ name: "Old", username: "u", password: "p" })]);
});

test("skips fully empty rows and unknown columns", () => {
  const csv = "name,color,password\nKeep,blue,pw\n,,\n";
  assert.deepEqual(parseVaultImport(csv), [f({ name: "Keep", password: "pw" })]);
});

test("rejects empty and item-less input", () => {
  assert.throws(() => parseVaultImport("   "), /empty/);
  assert.throws(() => parseVaultImport("name,password\n"), /no items/);
  assert.throws(() => parseVaultImport("{not json"), /not valid JSON/);
});
