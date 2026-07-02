// TOTP (RFC 6238) code generation for vault items that store another site's
// 2FA secret. Runs entirely on-device with WebCrypto; nothing is sent anywhere.
// This is for generating codes for OTHER services; passwd's own login 2FA is
// verified server-side and does not use this module.

export interface TotpConfig {
  secret: Uint8Array;
  algorithm: "SHA-1" | "SHA-256" | "SHA-512";
  digits: number;
  period: number; // seconds
}

// Accepts what users actually paste: a bare base32 secret (spaces/dashes/padding
// tolerated, any case) or a full otpauth://totp/... URI. Returns null when the
// input can't yield a usable secret.
export function parseTotpSecret(input: string): TotpConfig | null {
  const raw = input.trim();
  if (!raw) return null;
  if (/^otpauth:\/\//i.test(raw)) {
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      return null;
    }
    const secret = base32Decode(url.searchParams.get("secret") ?? "");
    if (!secret) return null;
    const alg = (url.searchParams.get("algorithm") ?? "SHA1").toUpperCase().replace("SHA", "SHA-");
    const digits = parseInt(url.searchParams.get("digits") ?? "6", 10);
    const period = parseInt(url.searchParams.get("period") ?? "30", 10);
    return {
      secret,
      algorithm: alg === "SHA-256" || alg === "SHA-512" ? alg : "SHA-1",
      digits: digits >= 6 && digits <= 10 ? digits : 6,
      period: period > 0 && period <= 300 ? period : 30,
    };
  }
  const secret = base32Decode(raw);
  if (!secret) return null;
  return { secret, algorithm: "SHA-1", digits: 6, period: 30 };
}

// RFC 4648 base32, case-insensitive, ignoring padding, spaces, and dashes.
// Returns null on any other character or empty input.
export function base32Decode(s: string): Uint8Array | null {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = s.toUpperCase().replace(/[\s-]/g, "").replace(/=+$/, "");
  if (!clean) return null;
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = alphabet.indexOf(ch);
    if (idx === -1) return null;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

// HOTP (RFC 4226): HMAC over the big-endian counter, dynamic truncation,
// zero-padded decimal output.
export async function hotp(cfg: Omit<TotpConfig, "period">, counter: number): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    cfg.secret as BufferSource,
    { name: "HMAC", hash: cfg.algorithm },
    false,
    ["sign"],
  );
  const msg = new ArrayBuffer(8);
  const view = new DataView(msg);
  // JS numbers hold 2^53 safely; TOTP counters stay far below that.
  view.setUint32(0, Math.floor(counter / 0x100000000));
  view.setUint32(4, counter >>> 0);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg));
  const offset = mac[mac.length - 1]! & 0x0f;
  const bin =
    ((mac[offset]! & 0x7f) << 24) | (mac[offset + 1]! << 16) | (mac[offset + 2]! << 8) | mac[offset + 3]!;
  return String(bin % 10 ** cfg.digits).padStart(cfg.digits, "0");
}

// Current TOTP code plus how long it stays valid.
export async function totpCode(
  cfg: TotpConfig,
  nowMs = Date.now(),
): Promise<{ code: string; secondsLeft: number }> {
  const step = Math.floor(nowMs / 1000 / cfg.period);
  const code = await hotp(cfg, step);
  const secondsLeft = cfg.period - (Math.floor(nowMs / 1000) % cfg.period);
  return { code, secondsLeft };
}

// One-call convenience for a stored `item.totp` string. Null when the stored
// value isn't a usable secret.
export async function totpFromString(
  stored: string,
  nowMs = Date.now(),
): Promise<{ code: string; secondsLeft: number; period: number } | null> {
  const cfg = parseTotpSecret(stored);
  if (!cfg) return null;
  const { code, secondsLeft } = await totpCode(cfg, nowMs);
  return { code, secondsLeft, period: cfg.period };
}
