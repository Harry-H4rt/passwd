import { test } from "node:test";
import assert from "node:assert/strict";
import { parseVaultImport, toCSV, toPlaintextJSON, EXPORT_FORMAT } from "./portable.js";

const item = {
  name: "GitHub",
  url: "https://github.com",
  username: "octocat",
  password: "p@ss,word\n\"quoted\"",
  notes: "line1\nline2",
};

test("plaintext JSON export round-trips through import", () => {
  const json = toPlaintextJSON([item]);
  assert.equal(JSON.parse(json).format, EXPORT_FORMAT);
  const back = parseVaultImport(json);
  assert.deepEqual(back, [item]);
});

test("CSV export escapes commas, quotes and newlines, and round-trips", () => {
  const csv = toCSV([item]);
  const back = parseVaultImport(csv);
  assert.deepEqual(back, [item]);
});

test("imports a Bitwarden-style CSV with aliased headers", () => {
  const csv = "name,login_uri,login_username,login_password,notes\nMail,https://mail.com,me@x.com,secret,hello";
  assert.deepEqual(parseVaultImport(csv), [
    { name: "Mail", url: "https://mail.com", username: "me@x.com", password: "secret", notes: "hello" },
  ]);
});

test("imports a Chrome-style CSV (name,url,username,password)", () => {
  const csv = "name,url,username,password\nSite,https://s.com,user,pw";
  assert.deepEqual(parseVaultImport(csv), [
    { name: "Site", url: "https://s.com", username: "user", password: "pw", notes: "" },
  ]);
});

test("accepts a bare JSON array and maps title/uri aliases", () => {
  const json = JSON.stringify([{ title: "X", uri: "https://x.com", username: "u", password: "p" }]);
  assert.deepEqual(parseVaultImport(json), [
    { name: "X", url: "https://x.com", username: "u", password: "p", notes: "" },
  ]);
});

test("skips fully empty rows and unknown columns", () => {
  const csv = "name,color,password\nKeep,blue,pw\n,,\n";
  assert.deepEqual(parseVaultImport(csv), [
    { name: "Keep", url: "", username: "", password: "pw", notes: "" },
  ]);
});

test("rejects empty and item-less input", () => {
  assert.throws(() => parseVaultImport("   "), /empty/);
  assert.throws(() => parseVaultImport("name,password\n"), /no items/);
  assert.throws(() => parseVaultImport("{not json"), /not valid JSON/);
});
