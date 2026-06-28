// Bridges @passwd/crypto with the API. All encryption/decryption happens here,
// client-side; the access token and in-memory user key live only in JS memory and
// are dropped on lock.

import {
  buildRegistration,
  deriveMasterKey,
  deriveMasterPasswordHash,
  stretchMasterKey,
  unwrapUserKey,
  encryptItem,
  decryptItem,
  generateAccountId,
  DEFAULT_KDF,
} from "@passwd/crypto";
import * as api from "./api.js";

export interface Session {
  identifier: string;
  accessToken: string;
  refreshToken: string;
  userKey: Uint8Array;
}

// Decrypted vault item. `id` is the server cipher id; the rest is encrypted.
export interface VaultItem {
  id: string;
  name: string;
  username: string;
  password: string;
  url: string;
  notes: string;
}

export type ItemFields = Omit<VaultItem, "id">;

export const newAccountId = () => generateAccountId();

// Thrown by loginAccount when the account has 2FA enabled and no/invalid code was
// supplied. The UI should prompt for a code and call loginAccount again with it.
export class TwoFactorRequiredError extends Error {
  constructor() {
    super("two-factor authentication required");
    this.name = "TwoFactorRequiredError";
  }
}

export async function registerAccount(identifier: string, masterPassword: string): Promise<Session> {
  const { bundle, userKey } = await buildRegistration(identifier, masterPassword, DEFAULT_KDF);
  await api.register(bundle);
  const res = await api.login(bundle.identifier, bundle.masterPasswordHash);
  if ("twoFactorRequired" in res && res.twoFactorRequired) {
    throw new Error("unexpected two-factor challenge on a new account");
  }
  return { identifier: bundle.identifier, accessToken: res.accessToken, refreshToken: res.refreshToken, userKey };
}

export async function loginAccount(
  identifier: string,
  masterPassword: string,
  totpCode?: string,
): Promise<Session> {
  const { kdf } = await api.prelogin(identifier);
  // Derive the master key once; reuse it for both the auth hash and unwrapping.
  const masterKey = await deriveMasterKey(masterPassword, identifier, kdf);
  const masterPasswordHash = await deriveMasterPasswordHash(masterKey, masterPassword);
  const res = await api.login(identifier, masterPasswordHash, totpCode);
  if ("twoFactorRequired" in res && res.twoFactorRequired) {
    throw new TwoFactorRequiredError();
  }
  const stretched = await stretchMasterKey(masterKey);
  const userKey = await unwrapUserKey(stretched, res.protectedUserKey);
  return { identifier, accessToken: res.accessToken, refreshToken: res.refreshToken, userKey };
}

// --- two-factor (TOTP) ------------------------------------------------------

export const getTwoFactorStatus = (s: Session) => api.twoFactorStatus(s.accessToken);

export async function setupTwoFactor(s: Session): Promise<{ secret: string; otpauthUri: string }> {
  const { secret } = await api.twoFactorSetup(s.accessToken);
  return { secret, otpauthUri: buildOtpauthUri(s.identifier, secret) };
}

export const enableTwoFactor = (s: Session, code: string) => api.twoFactorEnable(s.accessToken, code);
export const disableTwoFactor = (s: Session, code: string) => api.twoFactorDisable(s.accessToken, code);

// Built client-side so the plaintext identifier (used as the account label) never
// reaches the server.
export function buildOtpauthUri(identifier: string, secret: string): string {
  const label = encodeURIComponent(`passwd:${identifier}`);
  const params = new URLSearchParams({
    secret,
    issuer: "passwd",
    algorithm: "SHA1",
    digits: "6",
    period: "30",
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

export async function loadVault(s: Session): Promise<VaultItem[]> {
  const { ciphers } = await api.sync(s.accessToken);
  const items: VaultItem[] = [];
  for (const c of ciphers) {
    try {
      const fields = JSON.parse(await decryptItem(s.userKey, c.data)) as ItemFields;
      items.push({ id: c.id, ...blankFields(), ...fields });
    } catch {
      // skip undecryptable items rather than break the whole vault
    }
  }
  return items;
}

export async function addItem(s: Session, fields: ItemFields): Promise<VaultItem> {
  const data = await encryptItem(s.userKey, JSON.stringify(fields));
  const c = await api.createCipher(s.accessToken, data);
  return { id: c.id, ...fields };
}

export async function saveItem(s: Session, item: VaultItem): Promise<void> {
  const { id, ...fields } = item;
  const data = await encryptItem(s.userKey, JSON.stringify(fields));
  await api.updateCipher(s.accessToken, id, data);
}

export async function removeItem(s: Session, id: string): Promise<void> {
  await api.deleteCipher(s.accessToken, id);
}

// Bulk-add imported items, encrypting each client-side. Reports progress and
// counts failures rather than aborting the whole import on one bad item.
export async function importItems(
  s: Session,
  items: ItemFields[],
  onProgress?: (done: number, total: number) => void,
): Promise<{ added: number; failed: number }> {
  let added = 0;
  let failed = 0;
  for (let i = 0; i < items.length; i++) {
    try {
      await addItem(s, items[i]!);
      added++;
    } catch {
      failed++;
    }
    onProgress?.(i + 1, items.length);
  }
  return { added, failed };
}

export function blankFields(): ItemFields {
  return { name: "", username: "", password: "", url: "", notes: "" };
}

// A simple strong password generator for the "generate" button.
export function generatePassword(length = 20): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+";
  const out: string[] = [];
  const buf = new Uint32Array(length);
  crypto.getRandomValues(buf);
  for (let i = 0; i < length; i++) out.push(alphabet[buf[i]! % alphabet.length]!);
  return out.join("");
}
