// Thin typed client for the passwd backend. Transport only — it sends/receives
// the ciphertext produced by @passwd/crypto and never handles plaintext secrets.

import type { KdfParams } from "@passwd/crypto";

// The KDF descriptor crosses the wire verbatim; reuse the crypto package's type.
export type Kdf = KdfParams;

export interface LoginResult {
  accessToken: string;
  refreshToken: string;
  protectedUserKey: string;
  kdf: Kdf;
}

export interface CipherDto {
  id: string;
  data: string;
  createdAt: string;
  updatedAt: string;
}

export interface RegistrationBundle {
  identifier: string;
  kdf: Kdf;
  masterPasswordHash: string;
  protectedUserKey: string;
}

async function call<T>(method: string, path: string, body?: unknown, token?: string): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (token) headers["authorization"] = `Bearer ${token}`;
  const res = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  const json = text ? JSON.parse(text) : {};
  if (!res.ok) {
    throw new Error(json.error || `request failed (${res.status})`);
  }
  return json as T;
}

export const prelogin = (identifier: string) =>
  call<{ kdf: Kdf }>("POST", "/api/accounts/prelogin", { identifier });

export const register = (bundle: RegistrationBundle) =>
  call<{ id: string }>("POST", "/api/accounts/register", bundle);

export const login = (identifier: string, masterPasswordHash: string) =>
  call<LoginResult>("POST", "/api/auth/login", { identifier, masterPasswordHash });

export const sync = (token: string) =>
  call<{ ciphers: CipherDto[] }>("GET", "/api/sync", undefined, token);

export const createCipher = (token: string, data: string) =>
  call<CipherDto>("POST", "/api/ciphers", { data }, token);

export const updateCipher = (token: string, id: string, data: string) =>
  call<CipherDto>("PUT", `/api/ciphers/${id}`, { data }, token);

export const deleteCipher = (token: string, id: string) =>
  call<void>("DELETE", `/api/ciphers/${id}`, undefined, token);
