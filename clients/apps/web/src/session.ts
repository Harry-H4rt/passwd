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
import * as api from "./api";

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

export async function registerAccount(identifier: string, masterPassword: string): Promise<Session> {
  const { bundle, userKey } = await buildRegistration(identifier, masterPassword, DEFAULT_KDF);
  await api.register(bundle);
  const res = await api.login(bundle.identifier, bundle.masterPasswordHash);
  return { identifier: bundle.identifier, accessToken: res.accessToken, refreshToken: res.refreshToken, userKey };
}

export async function loginAccount(identifier: string, masterPassword: string): Promise<Session> {
  const { kdf } = await api.prelogin(identifier);
  // Derive the master key once; reuse it for both the auth hash and unwrapping.
  const masterKey = await deriveMasterKey(masterPassword, identifier, kdf);
  const masterPasswordHash = await deriveMasterPasswordHash(masterKey, masterPassword);
  const res = await api.login(identifier, masterPasswordHash);
  const stretched = await stretchMasterKey(masterKey);
  const userKey = await unwrapUserKey(stretched, res.protectedUserKey);
  return { identifier, accessToken: res.accessToken, refreshToken: res.refreshToken, userKey };
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
