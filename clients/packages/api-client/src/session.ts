// Bridges @passwd/crypto with the API. All encryption/decryption happens here,
// client-side; the access token and in-memory user key live only in JS memory and
// are dropped on lock.

import {
  buildRegistration,
  deriveMasterKey,
  deriveMasterPasswordHash,
  stretchMasterKey,
  unwrapUserKey,
  encryptItemKeyed,
  decryptItemKeyed,
  generateAccountId,
  enrollRecovery,
  completeRecovery,
  createShare,
  openShare,
  DEFAULT_KDF,
} from "@passwd/crypto";
import { startRegistration, startAuthentication } from "@simplewebauthn/browser";
import * as api from "./api.js";

export interface Session {
  identifier: string;
  accessToken: string;
  refreshToken: string;
  userKey: Uint8Array;
  // The User-Key-wrapped sharing private key, returned at login. Empty for accounts
  // created before sharing existed; needed to open items shared to this user.
  protectedPrivateKey: string;
}

// A vault item received from another user, decrypted locally.
export interface SharedItem extends VaultItem {
  shareId: string;
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

// Thrown by loginAccount when the account has 2FA enabled and no factor was
// supplied. `methods` lists the enrolled factors ("webauthn", "totp") so the UI can
// offer a choice: retry loginAccount with a TOTP code, or call loginWithPasskey.
export class TwoFactorRequiredError extends Error {
  methods: string[];
  constructor(methods: string[] = []) {
    super("two-factor authentication required");
    this.name = "TwoFactorRequiredError";
    this.methods = methods;
  }
}

export async function registerAccount(identifier: string, masterPassword: string): Promise<Session> {
  const { bundle, userKey } = await buildRegistration(identifier, masterPassword, DEFAULT_KDF);
  await api.register(bundle);
  const res = await api.login(bundle.identifier, bundle.masterPasswordHash);
  if ("twoFactorRequired" in res && res.twoFactorRequired) {
    throw new Error("unexpected two-factor challenge on a new account");
  }
  return {
    identifier: bundle.identifier,
    accessToken: res.accessToken,
    refreshToken: res.refreshToken,
    userKey,
    protectedPrivateKey: bundle.protectedPrivateKey,
  };
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
    throw new TwoFactorRequiredError(res.methods);
  }
  const stretched = await stretchMasterKey(masterKey);
  const userKey = await unwrapUserKey(stretched, res.protectedUserKey);
  return {
    identifier,
    accessToken: res.accessToken,
    refreshToken: res.refreshToken,
    userKey,
    protectedPrivateKey: res.protectedPrivateKey ?? "",
  };
}

// Completes a passkey (WebAuthn) second-factor login. The password is verified
// first (same derivation as loginAccount), then the server issues an assertion
// challenge which the authenticator signs. Call this when a TwoFactorRequiredError
// lists "webauthn" among its methods.
export async function loginWithPasskey(identifier: string, masterPassword: string): Promise<Session> {
  const { kdf } = await api.prelogin(identifier);
  const masterKey = await deriveMasterKey(masterPassword, identifier, kdf);
  const masterPasswordHash = await deriveMasterPasswordHash(masterKey, masterPassword);
  const { sessionId, options } = await api.webauthnLoginBegin(identifier, masterPasswordHash);
  const assertion = await startAuthentication({ optionsJSON: options.publicKey });
  const res = await api.webauthnLoginFinish(identifier, masterPasswordHash, sessionId, assertion);
  const stretched = await stretchMasterKey(masterKey);
  const userKey = await unwrapUserKey(stretched, res.protectedUserKey);
  return {
    identifier,
    accessToken: res.accessToken,
    refreshToken: res.refreshToken,
    userKey,
    protectedPrivateKey: res.protectedPrivateKey ?? "",
  };
}

// --- two-factor (TOTP) ------------------------------------------------------

export const getTwoFactorStatus = (s: Session) => api.twoFactorStatus(s.accessToken);

export async function setupTwoFactor(s: Session): Promise<{ secret: string; otpauthUri: string }> {
  const { secret } = await api.twoFactorSetup(s.accessToken);
  return { secret, otpauthUri: buildOtpauthUri(s.identifier, secret) };
}

export const enableTwoFactor = (s: Session, code: string) => api.twoFactorEnable(s.accessToken, code);
export const disableTwoFactor = (s: Session, code: string) => api.twoFactorDisable(s.accessToken, code);

// --- account recovery -------------------------------------------------------

export const getRecoveryStatus = (s: Session) => api.recoveryStatus(s.accessToken);

// Generate a recovery code, wrap the (unlocked) User Key under it, and upload the
// wrapped key + verifier. Returns the recovery code to show the user exactly once
// — it is never stored and cannot be recovered if lost.
export async function enableRecovery(s: Session): Promise<string> {
  const { recoveryCode, recoveryProtectedUserKey, recoveryAuthHash } = await enrollRecovery(s.userKey);
  await api.recoveryEnable(s.accessToken, recoveryProtectedUserKey, recoveryAuthHash);
  return recoveryCode;
}

export const disableRecovery = (s: Session) => api.recoveryDisable(s.accessToken);

// --- security activity (audit log) ------------------------------------------

export type ActivityEvent = api.AuditEvent;

export const getActivity = (s: Session) =>
  api.auditLog(s.accessToken).then((r) => r.events);

// Forgot-password recovery: fetch the recovery-wrapped key, unwrap it with the
// recovery code, set a NEW master password, and log in. The User Key is unchanged,
// so existing vault items remain decryptable. A wrong code (or unknown account)
// fails when the recovery-wrapped key won't decrypt.
export async function recoverAccount(
  identifier: string,
  recoveryCode: string,
  newMasterPassword: string,
): Promise<Session> {
  const { recoveryProtectedUserKey, kdf } = await api.recoveryChallenge(identifier);
  const reset = await completeRecovery(
    recoveryCode,
    recoveryProtectedUserKey,
    identifier,
    newMasterPassword,
    kdf,
  );
  const res = await api.recoveryComplete({
    identifier,
    recoveryAuthHash: reset.recoveryAuthHash,
    masterPasswordHash: reset.masterPasswordHash,
    protectedUserKey: reset.protectedUserKey,
    kdf: reset.kdf,
  });
  return {
    identifier,
    accessToken: res.accessToken,
    refreshToken: res.refreshToken,
    userKey: reset.userKey,
    protectedPrivateKey: res.protectedPrivateKey ?? "",
  };
}

// --- item sharing -----------------------------------------------------------

// Share a vault item with another user: look up their public key, encrypt the
// item to it, and upload. The recipient's identifier is needed to find them.
export async function shareItem(s: Session, recipientIdentifier: string, item: VaultItem): Promise<void> {
  const { publicKey } = await api.lookupPublicKey(s.accessToken, recipientIdentifier);
  const { id: _id, ...fields } = item;
  const envelope = await createShare(publicKey, JSON.stringify(fields));
  await api.createShare(s.accessToken, {
    recipientIdentifier,
    wrappedKey: envelope.wrappedKey,
    data: envelope.data,
  });
}

// List items shared with the current user, decrypted locally with their private key.
export async function listSharedWithMe(s: Session): Promise<SharedItem[]> {
  const { shares } = await api.listShares(s.accessToken);
  const items: SharedItem[] = [];
  for (const sh of shares) {
    try {
      const fields = JSON.parse(
        await openShare(s.userKey, s.protectedPrivateKey, { wrappedKey: sh.wrappedKey, data: sh.data }),
      ) as ItemFields;
      items.push({ id: sh.id, shareId: sh.id, ...blankFields(), ...fields });
    } catch {
      // skip shares we can't decrypt
    }
  }
  return items;
}

export const removeSharedItem = (s: Session, shareId: string) => api.deleteShare(s.accessToken, shareId);

// --- passkeys (WebAuthn) ----------------------------------------------------

export const listPasskeys = (s: Session) =>
  api.webauthnCredentials(s.accessToken).then((r) => r.credentials);

export const removePasskey = (s: Session, id: string) =>
  api.webauthnDeleteCredential(s.accessToken, id);

// Enrolls a new passkey: the server issues creation options, the authenticator
// creates the keypair (prompting biometric/PIN), and the attestation is verified
// and stored server-side. `name` is a user-facing label.
export async function enrollPasskey(s: Session, name: string): Promise<{ id: string; name: string }> {
  const { sessionId, options } = await api.webauthnRegisterBegin(s.accessToken);
  const attestation = await startRegistration({ optionsJSON: options.publicKey });
  return api.webauthnRegisterFinish(s.accessToken, sessionId, name, attestation);
}

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
      const fields = JSON.parse(await decryptItemKeyed(s.userKey, c.data)) as ItemFields;
      items.push({ id: c.id, ...blankFields(), ...fields });
    } catch {
      // skip undecryptable items rather than break the whole vault
    }
  }
  return items;
}

export async function addItem(s: Session, fields: ItemFields): Promise<VaultItem> {
  const data = await encryptItemKeyed(s.userKey, JSON.stringify(fields));
  const c = await api.createCipher(s.accessToken, data);
  return { id: c.id, ...fields };
}

export async function saveItem(s: Session, item: VaultItem): Promise<void> {
  const { id, ...fields } = item;
  const data = await encryptItemKeyed(s.userKey, JSON.stringify(fields));
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
