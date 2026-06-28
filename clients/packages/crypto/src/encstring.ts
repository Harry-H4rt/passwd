import { fromBase64, toBase64 } from "./primitives.js";

// Self-describing ciphertext envelope: "<type>.<base64(nonce)>|<base64(data)>".
// The leading type byte keeps us crypto-agile; parsers reject unknown types.
export enum EncType {
  AesGcm = 1,
  AesCbcHmac = 2, // reserved for Bitwarden-compat import; not implemented yet
}

export interface EncString {
  type: EncType;
  nonce: Uint8Array;
  data: Uint8Array; // ciphertext + auth tag
}

export function serializeEncString(e: EncString): string {
  return `${e.type}.${toBase64(e.nonce)}|${toBase64(e.data)}`;
}

export function parseEncString(s: string): EncString {
  const dot = s.indexOf(".");
  if (dot < 0) throw new Error("invalid EncString: missing type prefix");
  const type = Number(s.slice(0, dot));
  if (type !== EncType.AesGcm) throw new Error(`unsupported EncString type: ${type}`);
  const parts = s.slice(dot + 1).split("|");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw new Error("invalid EncString: expected nonce|data");
  }
  return { type, nonce: fromBase64(parts[0]), data: fromBase64(parts[1]) };
}
