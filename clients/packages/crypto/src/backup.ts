// Portable, passphrase-protected backup envelope. Used for encrypted vault
// exports: the backup passphrase is independent of the account master password,
// so a backup can be restored on a fresh account or a different tool. The plain
// vault data is AES-GCM encrypted under an argon2id key; only the ciphertext,
// the public KDF params, and random salt/nonce land in the file.

import { DEFAULT_KDF, type KdfParams, deriveKey } from "./kdf.js";
import { aesGcmDecrypt, aesGcmEncrypt, fromBase64, fromUtf8, randomBytes, toBase64, utf8 } from "./primitives.js";

export const BACKUP_FORMAT = "passwd-backup";
export const BACKUP_VERSION = 1;

export interface BackupEnvelope {
  format: typeof BACKUP_FORMAT;
  version: number;
  kdf: KdfParams;
  salt: string; // base64, fed to the KDF
  nonce: string; // base64, AES-GCM IV
  data: string; // base64 ciphertext (includes the GCM tag)
}

// Encrypt arbitrary plaintext under a passphrase, returning a self-describing
// JSON envelope string suitable for writing to a file.
export async function encryptBackup(
  plaintext: string,
  passphrase: string,
  params: KdfParams = DEFAULT_KDF,
): Promise<string> {
  if (!passphrase) throw new Error("a backup passphrase is required");
  const salt = toBase64(randomBytes(16));
  const key = await deriveKey(passphrase, salt, params);
  const { nonce, ciphertext } = await aesGcmEncrypt(key, utf8(plaintext));
  const env: BackupEnvelope = {
    format: BACKUP_FORMAT,
    version: BACKUP_VERSION,
    kdf: params,
    salt,
    nonce: toBase64(nonce),
    data: toBase64(ciphertext),
  };
  return JSON.stringify(env, null, 2);
}

// Reverse encryptBackup. Throws a friendly error on a bad file or wrong
// passphrase (GCM auth failure).
export async function decryptBackup(envelope: string, passphrase: string): Promise<string> {
  let env: BackupEnvelope;
  try {
    env = JSON.parse(envelope) as BackupEnvelope;
  } catch {
    throw new Error("not a valid passwd backup file");
  }
  if (env?.format !== BACKUP_FORMAT) throw new Error("not a passwd backup file");
  if (env.version !== BACKUP_VERSION) throw new Error(`unsupported backup version ${env.version}`);
  const key = await deriveKey(passphrase, env.salt, env.kdf);
  try {
    return fromUtf8(await aesGcmDecrypt(key, fromBase64(env.nonce), fromBase64(env.data)));
  } catch {
    throw new Error("wrong passphrase or corrupted backup");
  }
}

// Cheap check (no decryption) for whether a file looks like an encrypted backup,
// so callers can decide whether to prompt for a passphrase.
export function isBackupEnvelope(text: string): boolean {
  try {
    return (JSON.parse(text) as Partial<BackupEnvelope>)?.format === BACKUP_FORMAT;
  } catch {
    return false;
  }
}
