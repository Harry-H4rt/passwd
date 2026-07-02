import { test } from "node:test";
import assert from "node:assert/strict";
import { base32Decode, hotp, totpCode, parseTotpSecret, totpFromString } from "./totp.js";

const ascii = (s: string) => new TextEncoder().encode(s);

// RFC 4226 appendix D: secret "12345678901234567890", 6-digit SHA-1 HOTP.
test("hotp matches the RFC 4226 test vectors", async () => {
  const cfg = { secret: ascii("12345678901234567890"), algorithm: "SHA-1", digits: 6 } as const;
  const expected = ["755224", "287082", "359152", "969429", "338314", "254676"];
  for (let i = 0; i < expected.length; i++) {
    assert.equal(await hotp(cfg, i), expected[i]);
  }
});

// RFC 6238 appendix B (8-digit codes; per-algorithm ASCII secrets).
test("totp matches the RFC 6238 test vectors", async () => {
  const cases: Array<["SHA-1" | "SHA-256" | "SHA-512", string, number, string]> = [
    ["SHA-1", "12345678901234567890", 59, "94287082"],
    ["SHA-256", "12345678901234567890123456789012", 59, "46119246"],
    ["SHA-512", "1234567890123456789012345678901234567890123456789012345678901234", 59, "90693936"],
    ["SHA-1", "12345678901234567890", 1111111109, "07081804"],
    ["SHA-1", "12345678901234567890", 1234567890, "89005924"],
    ["SHA-256", "12345678901234567890123456789012", 20000000000, "77737706"],
  ];
  for (const [algorithm, secret, t, expected] of cases) {
    const { code } = await totpCode({ secret: ascii(secret), algorithm, digits: 8, period: 30 }, t * 1000);
    assert.equal(code, expected);
  }
});

test("base32 decodes RFC 4648 vectors and tolerates mess", () => {
  assert.deepEqual(base32Decode("MZXW6YTBOI======"), ascii("foobar"));
  assert.deepEqual(base32Decode("mzxw 6ytb-oi"), ascii("foobar"));
  assert.equal(base32Decode("1890"), null); // 1, 8, 9, 0 are not base32
  assert.equal(base32Decode(""), null);
});

test("parseTotpSecret handles bare secrets and otpauth URIs", () => {
  const bare = parseTotpSecret("jbsw y3dp ehpk 3pxp");
  assert.ok(bare);
  assert.equal(bare.digits, 6);
  assert.equal(bare.period, 30);
  assert.equal(bare.algorithm, "SHA-1");

  const uri = parseTotpSecret(
    "otpauth://totp/Example:me@x.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60",
  );
  assert.ok(uri);
  assert.equal(uri.algorithm, "SHA-256");
  assert.equal(uri.digits, 8);
  assert.equal(uri.period, 60);

  assert.equal(parseTotpSecret(""), null);
  assert.equal(parseTotpSecret("not!base32"), null);
  assert.equal(parseTotpSecret("otpauth://totp/x?digits=6"), null); // no secret
});

test("totpFromString computes a code and countdown", async () => {
  const r = await totpFromString("JBSWY3DPEHPK3PXP", 59_000);
  assert.ok(r);
  assert.match(r.code, /^\d{6}$/);
  assert.equal(r.secondsLeft, 1); // 59s into a 30s window: 1s left
  assert.equal(r.period, 30);
  assert.equal(await totpFromString("###"), null);
});

test("consecutive windows give different codes", async () => {
  const cfg = parseTotpSecret("JBSWY3DPEHPK3PXP")!;
  const a = await totpCode(cfg, 0);
  const b = await totpCode(cfg, 30_000);
  assert.notEqual(a.code, b.code);
});
