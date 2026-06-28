// Low-level crypto primitives over the WebCrypto API (browser + Node 20+).
// No secrets are logged or persisted here.

const subtle = globalThis.crypto.subtle;

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function fromUtf8(b: Uint8Array): string {
  return new TextDecoder().decode(b);
}

export function toBase64(b: Uint8Array): string {
  let s = "";
  for (const byte of b) s += String.fromCharCode(byte);
  return btoa(s);
}

export function fromBase64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export interface AesGcmResult {
  nonce: Uint8Array; // 96-bit
  ciphertext: Uint8Array; // includes the 128-bit GCM tag
}

export async function aesGcmEncrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  nonce: Uint8Array = randomBytes(12),
): Promise<AesGcmResult> {
  const k = await subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
  const ct = await subtle.encrypt({ name: "AES-GCM", iv: nonce }, k, plaintext);
  return { nonce, ciphertext: new Uint8Array(ct) };
}

export async function aesGcmDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const k = await subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
  const pt = await subtle.decrypt({ name: "AES-GCM", iv: nonce }, k, ciphertext);
  return new Uint8Array(pt);
}

// HKDF-Expand only (RFC 5869 §2.3). The master key is used directly as the PRK,
// matching the Bitwarden scheme (the Extract step is skipped).
export async function hkdfExpand(prk: Uint8Array, info: string, length: number): Promise<Uint8Array> {
  const key = await subtle.importKey("raw", prk, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const infoBytes = utf8(info);
  const hashLen = 32;
  const blocks = Math.ceil(length / hashLen);
  const okm = new Uint8Array(blocks * hashLen);
  let prev = new Uint8Array(0);
  for (let i = 0; i < blocks; i++) {
    const input = new Uint8Array(prev.length + infoBytes.length + 1);
    input.set(prev, 0);
    input.set(infoBytes, prev.length);
    input[input.length - 1] = i + 1;
    prev = new Uint8Array(await subtle.sign("HMAC", key, input));
    okm.set(prev, i * hashLen);
  }
  return okm.slice(0, length);
}

export async function pbkdf2(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  length = 32,
): Promise<Uint8Array> {
  const k = await subtle.importKey("raw", password, "PBKDF2", false, ["deriveBits"]);
  const bits = await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, k, length * 8);
  return new Uint8Array(bits);
}
