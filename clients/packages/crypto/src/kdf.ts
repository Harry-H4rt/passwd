import { pbkdf2, utf8 } from "./primitives.js";

export type KdfType = "argon2id" | "pbkdf2";

export interface KdfParams {
  type: KdfType;
  iterations: number; // argon2 time cost OR pbkdf2 rounds
  memoryMiB?: number; // argon2 only
  parallelism?: number; // argon2 only
}

// Default for new accounts. Argon2id params follow Bitwarden's defaults and meet
// OWASP guidance. Must stay in sync with backend auth.DefaultKDF.
export const DEFAULT_KDF: KdfParams = {
  type: "argon2id",
  iterations: 3,
  memoryMiB: 64,
  parallelism: 4,
};

// Derive a 256-bit key from a password + salt under the given KDF.
export async function deriveKey(password: string, salt: string, params: KdfParams): Promise<Uint8Array> {
  const pw = utf8(password.normalize("NFKC"));
  const saltBytes = utf8(salt);

  if (params.type === "pbkdf2") {
    return pbkdf2(pw, saltBytes, params.iterations, 32);
  }

  // Argon2id. Lazy-imported so the package still works offline when only the
  // pbkdf2 path is exercised (e.g. unit tests without node_modules).
  const { argon2id } = await import("hash-wasm");
  const out = await argon2id({
    password: pw,
    salt: saltBytes,
    iterations: params.iterations,
    memorySize: (params.memoryMiB ?? 64) * 1024, // KiB
    parallelism: params.parallelism ?? 4,
    hashLength: 32,
    outputType: "binary",
  });
  return out as Uint8Array;
}
