// The account key hierarchy from docs/CRYPTO.md. Everything here runs client-side
// only; the server never imports this module.

import { type KdfParams, deriveKey } from "./kdf.js";
import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  fromUtf8,
  hkdfExpand,
  pbkdf2,
  randomBytes,
  toBase64,
  utf8,
} from "./primitives.js";
import { EncType, parseEncString, serializeEncString } from "./encstring.js";
import { generateAccountId, normalizeIdentifier } from "./identifier.js";

const USER_KEY_BYTES = 64; // 32 for AES-GCM + 32 reserved (per-item / CBC-HMAC compat)

export interface StretchedKey {
  encKey: Uint8Array; // 32 bytes, AES-GCM
  macKey: Uint8Array; // 32 bytes, reserved for CBC-HMAC compatibility
}

// Master Key = KDF(masterPassword, salt = normalize(identifier)). The identifier
// is the account's login handle (generated passphrase or email). Never leaves the
// device.
export async function deriveMasterKey(
  masterPassword: string,
  identifier: string,
  params: KdfParams,
): Promise<Uint8Array> {
  return deriveKey(masterPassword, normalizeIdentifier(identifier), params);
}

// Master Password Hash, the authentication credential sent to the server. One
// PBKDF2 pass over the master key, salted by the password (mirrors Bitwarden).
// The server stores Argon2id(this); it cannot recover the master key from it.
// TODO(Phase 1): freeze this definition and publish known-answer test vectors.
export async function deriveMasterPasswordHash(
  masterKey: Uint8Array,
  masterPassword: string,
): Promise<string> {
  const hash = await pbkdf2(masterKey, utf8(masterPassword.normalize("NFKC")), 1, 32);
  return toBase64(hash);
}

// Stretch the 256-bit master key into two 256-bit subkeys via HKDF-Expand.
export async function stretchMasterKey(masterKey: Uint8Array): Promise<StretchedKey> {
  return {
    encKey: await hkdfExpand(masterKey, "enc", 32),
    macKey: await hkdfExpand(masterKey, "mac", 32),
  };
}

export function generateUserKey(): Uint8Array {
  return randomBytes(USER_KEY_BYTES);
}

function itemKey(userKey: Uint8Array): Uint8Array {
  return userKey.slice(0, 32);
}

// Wrap the user key with the stretched master key → ProtectedUserKey EncString.
export async function wrapUserKey(stretched: StretchedKey, userKey: Uint8Array): Promise<string> {
  const { nonce, ciphertext } = await aesGcmEncrypt(stretched.encKey, userKey);
  return serializeEncString({ type: EncType.AesGcm, nonce, data: ciphertext });
}

export async function unwrapUserKey(stretched: StretchedKey, protectedUserKey: string): Promise<Uint8Array> {
  const e = parseEncString(protectedUserKey);
  return aesGcmDecrypt(stretched.encKey, e.nonce, e.data);
}

export async function encryptItem(userKey: Uint8Array, plaintext: string): Promise<string> {
  const { nonce, ciphertext } = await aesGcmEncrypt(itemKey(userKey), utf8(plaintext));
  return serializeEncString({ type: EncType.AesGcm, nonce, data: ciphertext });
}

export async function decryptItem(userKey: Uint8Array, encString: string): Promise<string> {
  const e = parseEncString(encString);
  return fromUtf8(await aesGcmDecrypt(itemKey(userKey), e.nonce, e.data));
}

// --- High-level flows -------------------------------------------------------

export interface RegistrationBundle {
  // The plaintext identifier. The client sends this to the server only as a login
  // credential; the server immediately blinds it (HMAC) and never stores it raw.
  identifier: string;
  kdf: KdfParams;
  masterPasswordHash: string;
  protectedUserKey: string;
}

// Build everything the server needs at registration, plus the in-memory user key.
export async function buildRegistration(
  identifier: string,
  masterPassword: string,
  params: KdfParams,
): Promise<{ bundle: RegistrationBundle; userKey: Uint8Array }> {
  const masterKey = await deriveMasterKey(masterPassword, identifier, params);
  const stretched = await stretchMasterKey(masterKey);
  const userKey = generateUserKey();
  const protectedUserKey = await wrapUserKey(stretched, userKey);
  const masterPasswordHash = await deriveMasterPasswordHash(masterKey, masterPassword);
  return {
    bundle: { identifier: normalizeIdentifier(identifier), kdf: params, masterPasswordHash, protectedUserKey },
    userKey,
  };
}

// Reproduce the user key + auth hash at login/unlock time.
export async function unlock(
  identifier: string,
  masterPassword: string,
  params: KdfParams,
  protectedUserKey: string,
): Promise<{ userKey: Uint8Array; masterPasswordHash: string }> {
  const masterKey = await deriveMasterKey(masterPassword, identifier, params);
  const stretched = await stretchMasterKey(masterKey);
  const userKey = await unwrapUserKey(stretched, protectedUserKey);
  const masterPasswordHash = await deriveMasterPasswordHash(masterKey, masterPassword);
  return { userKey, masterPasswordHash };
}

// --- Account recovery -------------------------------------------------------
//
// A Recovery Code is an independent, user-controlled way back into the vault if
// the master password is forgotten — never a server-side reset. It is a 24-word
// BIP39 phrase that wraps the *same* User Key, so recovering does not re-encrypt
// the vault. From the phrase we derive two subkeys (mirroring the master-password
// split): a recoveryEncKey that wraps the User Key, and a recoveryAuthHash that
// the server stores as a verifier — so it can authorize a master-password reset
// without ever learning the phrase, the User Key, or the new password.

const RECOVERY_KDF_SALT = "passwd.recovery.salt.v1";
const RECOVERY_KDF_ITERATIONS = 100_000;

export interface RecoveryKeys {
  recoveryEncKey: Uint8Array; // 32 bytes, AES-GCM, wraps the User Key
  recoveryAuthHash: string; // base64; sent to the server (verifier input)
}

// Derive recovery subkeys from the recovery phrase. The phrase carries ~264 bits
// of entropy, so a heavy KDF is not required for brute-force resistance; PBKDF2 +
// HKDF-Expand domain separation keeps it consistent with the rest of the design.
// normalizeIdentifier lets the user re-type the phrase with messy spacing/case.
export async function deriveRecoveryKeys(recoveryCode: string): Promise<RecoveryKeys> {
  const base = await pbkdf2(
    utf8(normalizeIdentifier(recoveryCode)),
    utf8(RECOVERY_KDF_SALT),
    RECOVERY_KDF_ITERATIONS,
    32,
  );
  return {
    recoveryEncKey: await hkdfExpand(base, "recovery-enc", 32),
    recoveryAuthHash: toBase64(await hkdfExpand(base, "recovery-auth", 32)),
  };
}

export async function wrapUserKeyWithRecovery(
  recoveryEncKey: Uint8Array,
  userKey: Uint8Array,
): Promise<string> {
  const { nonce, ciphertext } = await aesGcmEncrypt(recoveryEncKey, userKey);
  return serializeEncString({ type: EncType.AesGcm, nonce, data: ciphertext });
}

export async function unwrapUserKeyWithRecovery(
  recoveryEncKey: Uint8Array,
  recoveryProtectedUserKey: string,
): Promise<Uint8Array> {
  const e = parseEncString(recoveryProtectedUserKey);
  return aesGcmDecrypt(recoveryEncKey, e.nonce, e.data);
}

export interface RecoveryEnrollment {
  recoveryCode: string; // the 24-word phrase, shown to the user exactly once
  recoveryProtectedUserKey: string; // uploaded
  recoveryAuthHash: string; // uploaded (server stores Argon2id of it)
}

// Generate a recovery code plus everything the server needs to store, given the
// currently-unlocked User Key. Run only while the vault is unlocked.
export async function enrollRecovery(userKey: Uint8Array): Promise<RecoveryEnrollment> {
  const recoveryCode = generateAccountId(24);
  const { recoveryEncKey, recoveryAuthHash } = await deriveRecoveryKeys(recoveryCode);
  const recoveryProtectedUserKey = await wrapUserKeyWithRecovery(recoveryEncKey, userKey);
  return { recoveryCode, recoveryProtectedUserKey, recoveryAuthHash };
}

export interface RecoveryReset {
  recoveryAuthHash: string; // proves possession of the recovery code to the server
  masterPasswordHash: string; // new login credential
  protectedUserKey: string; // User Key re-wrapped under the new master password
  kdf: KdfParams;
  userKey: Uint8Array; // in-memory, for the now-unlocked session
}

// Recover the vault: unwrap the User Key with the recovery code, then re-wrap it
// under a NEW master password. The User Key itself is unchanged, so stored vault
// items stay valid (no re-encryption). Returns the recoveryAuthHash so the caller
// can prove to the server it may swap in the new credentials.
export async function completeRecovery(
  recoveryCode: string,
  recoveryProtectedUserKey: string,
  identifier: string,
  newMasterPassword: string,
  params: KdfParams,
): Promise<RecoveryReset> {
  const { recoveryEncKey, recoveryAuthHash } = await deriveRecoveryKeys(recoveryCode);
  const userKey = await unwrapUserKeyWithRecovery(recoveryEncKey, recoveryProtectedUserKey);
  const masterKey = await deriveMasterKey(newMasterPassword, identifier, params);
  const stretched = await stretchMasterKey(masterKey);
  const protectedUserKey = await wrapUserKey(stretched, userKey);
  const masterPasswordHash = await deriveMasterPasswordHash(masterKey, newMasterPassword);
  return { recoveryAuthHash, masterPasswordHash, protectedUserKey, kdf: params, userKey };
}
