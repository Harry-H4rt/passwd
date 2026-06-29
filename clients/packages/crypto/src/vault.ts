// Standalone, offline vault file for the desktop app (KeePass-style). A single
// self-describing JSON document that holds everything needed to unlock a vault with
// only a master password — no server, no stored verifier. The file reveals only the
// public KDF params, a random salt, and two ciphertexts: the wrapped User Key and
// the encrypted payload. A wrong password fails the AES-GCM auth tag, so there is
// nothing to brute-force offline beyond the KDF itself.
//
// Key handling mirrors the account hierarchy in account.ts:
//   masterKey = KDF(masterPassword, salt)          (Argon2id, ONCE at unlock)
//   stretched = HKDF(masterKey)
//   userKey   = random; protectedUserKey = wrap(stretched, userKey)
//   payload   = encryptItem(userKey, <app JSON>)   (fast AES-GCM on every save)
// Re-keying to a new password only re-wraps the same userKey, so saves never re-run
// the KDF and a password change never re-encrypts the payload.

import { DEFAULT_KDF, type KdfParams, deriveKey } from "./kdf.js";
import {
  decryptItem,
  encryptItem,
  generateUserKey,
  stretchMasterKey,
  unwrapUserKey,
  wrapUserKey,
} from "./account.js";
import { randomBytes, toBase64 } from "./primitives.js";

export const VAULT_FORMAT = "passwd-vault";
export const VAULT_VERSION = 1;

// The on-disk document. `vault` and `protectedUserKey` are EncStrings; everything
// else is public (non-secret) metadata.
export interface VaultFile {
  format: typeof VAULT_FORMAT;
  version: number;
  kdf: KdfParams;
  salt: string; // base64, fed to the KDF
  protectedUserKey: string; // EncString: userKey wrapped by the stretched master key
  vault: string; // EncString: app payload encrypted under the userKey
}

// In-memory unlocked state. `userKey` is sensitive and must be dropped on lock.
// Everything here except userKey is safe to keep/serialize.
export interface VaultState {
  kdf: KdfParams;
  salt: string;
  protectedUserKey: string;
  userKey: Uint8Array;
}

async function serialize(state: VaultState, payload: string): Promise<string> {
  const vault = await encryptItem(state.userKey, payload);
  const file: VaultFile = {
    format: VAULT_FORMAT,
    version: VAULT_VERSION,
    kdf: state.kdf,
    salt: state.salt,
    protectedUserKey: state.protectedUserKey,
    vault,
  };
  return JSON.stringify(file, null, 2);
}

// Create a brand-new vault around an initial payload string (e.g. an empty item
// list). Returns the file text to write to disk plus the unlocked in-memory state.
export async function createVault(
  masterPassword: string,
  payload: string,
  params: KdfParams = DEFAULT_KDF,
): Promise<{ file: string; state: VaultState }> {
  if (!masterPassword) throw new Error("a master password is required");
  const salt = toBase64(randomBytes(16));
  const masterKey = await deriveKey(masterPassword, salt, params);
  const stretched = await stretchMasterKey(masterKey);
  const userKey = generateUserKey();
  const protectedUserKey = await wrapUserKey(stretched, userKey);
  const state: VaultState = { kdf: params, salt, protectedUserKey, userKey };
  return { file: await serialize(state, payload), state };
}

// Open an existing vault file. Throws a friendly error on a malformed file or wrong
// password (both the unwrap and the payload decrypt are AES-GCM, so either failing
// means the same thing to the user: the password is wrong or the file is corrupt).
export async function openVault(
  fileText: string,
  masterPassword: string,
): Promise<{ state: VaultState; payload: string }> {
  let file: VaultFile;
  try {
    file = JSON.parse(fileText) as VaultFile;
  } catch {
    throw new Error("not a valid passwd vault file");
  }
  if (file?.format !== VAULT_FORMAT) throw new Error("not a passwd vault file");
  if (file.version !== VAULT_VERSION) throw new Error(`unsupported vault version ${file.version}`);

  const masterKey = await deriveKey(masterPassword, file.salt, file.kdf);
  const stretched = await stretchMasterKey(masterKey);
  try {
    const userKey = await unwrapUserKey(stretched, file.protectedUserKey);
    const payload = await decryptItem(userKey, file.vault);
    return {
      state: { kdf: file.kdf, salt: file.salt, protectedUserKey: file.protectedUserKey, userKey },
      payload,
    };
  } catch {
    throw new Error("wrong master password or corrupted vault");
  }
}

// Re-serialize the vault with a new payload. Fast: only the payload is re-encrypted
// (AES-GCM under the in-memory userKey); no KDF runs.
export function saveVault(state: VaultState, payload: string): Promise<string> {
  return serialize(state, payload);
}

// Re-key to a new master password: re-derive from the new password (fresh salt) and
// re-wrap the SAME userKey, so the payload is unchanged. Returns the new file text
// and state to replace the old ones.
export async function changeMasterPassword(
  state: VaultState,
  newPassword: string,
  payload: string,
  params: KdfParams = state.kdf,
): Promise<{ file: string; state: VaultState }> {
  if (!newPassword) throw new Error("a master password is required");
  const salt = toBase64(randomBytes(16));
  const masterKey = await deriveKey(newPassword, salt, params);
  const stretched = await stretchMasterKey(masterKey);
  const protectedUserKey = await wrapUserKey(stretched, state.userKey);
  const next: VaultState = { kdf: params, salt, protectedUserKey, userKey: state.userKey };
  return { file: await serialize(next, payload), state: next };
}

// Cheap structural check (no decryption) so a caller can tell a vault file from
// other JSON before prompting for a password.
export function isVaultFile(text: string): boolean {
  try {
    return (JSON.parse(text) as Partial<VaultFile>)?.format === VAULT_FORMAT;
  } catch {
    return false;
  }
}
