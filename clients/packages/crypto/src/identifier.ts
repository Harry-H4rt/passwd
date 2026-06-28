import { BIP39_WORDLIST } from "./wordlist.js";

// An account identifier is whatever the user logs in with: either a generated
// passphrase (privacy-first default) or an email (opt-in). The crypto layer
// treats them identically; the normalized identifier is the KDF salt, and the
// server only ever sees a blinded HMAC of it. See docs/CRYPTO.md.

// Canonical form used everywhere the identifier is hashed or salted. Trims, lower-
// cases, and collapses internal whitespace so "  Word  WORD " and a passphrase
// with stray spaces normalize consistently (and emails case-insensitively).
export function normalizeIdentifier(identifier: string): string {
  return identifier.trim().toLowerCase().replace(/\s+/g, " ");
}

// Generate a random account identifier as a space-separated passphrase drawn from
// the BIP39 wordlist. 12 words ≈ 132 bits of entropy. Uses rejection sampling to
// avoid modulo bias.
export function generateAccountId(words = 12): string {
  if (words < 1) throw new Error("words must be >= 1");
  const n = BIP39_WORDLIST.length; // 2048
  const limit = Math.floor(0x100000000 / n) * n; // largest multiple of n <= 2^32
  const out: string[] = [];
  const buf = new Uint32Array(1);
  while (out.length < words) {
    globalThis.crypto.getRandomValues(buf);
    const x = buf[0]!;
    if (x >= limit) continue; // reject to keep the distribution uniform
    out.push(BIP39_WORDLIST[x % n]!);
  }
  return out.join(" ");
}
