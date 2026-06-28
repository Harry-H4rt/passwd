// Thin typed client for the passwd backend. Transport only — it sends/receives
// the ciphertext produced by @passwd/crypto and never handles plaintext secrets.
//
// The base URL is configurable: the web vault leaves it "" (same-origin, via the
// Vite dev proxy / co-hosted in prod); the browser extension points it at the
// backend host (which it lists in host_permissions).

import type { KdfParams } from "@passwd/crypto";

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

let baseUrl = "";

export function configureApi(opts: { baseUrl: string }): void {
  baseUrl = opts.baseUrl.replace(/\/$/, "");
}

async function call<T>(method: string, path: string, body?: unknown, token?: string): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (token) headers["authorization"] = `Bearer ${token}`;
  const res = await fetch(baseUrl + path, {
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

// Login can succeed, or report that a second factor is required. We don't use
// call() here because the "2FA required" case is a 401 we want to handle, not throw.
export type LoginOutcome = (LoginResult & { twoFactorRequired?: false }) | { twoFactorRequired: true };

export async function login(
  identifier: string,
  masterPasswordHash: string,
  totpCode?: string,
): Promise<LoginOutcome> {
  const res = await fetch(baseUrl + "/api/auth/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ identifier, masterPasswordHash, totpCode }),
  });
  const json = await res.json().catch(() => ({}));
  if (res.ok) return json as LoginResult;
  if (res.status === 401 && json.twoFactorRequired) return { twoFactorRequired: true };
  throw new Error(json.error || `login failed (${res.status})`);
}

export const twoFactorStatus = (token: string) =>
  call<{ enabled: boolean }>("GET", "/api/2fa", undefined, token);

export const twoFactorSetup = (token: string) =>
  call<{ secret: string }>("POST", "/api/2fa/setup", {}, token);

export const twoFactorEnable = (token: string, code: string) =>
  call<{ enabled: boolean }>("POST", "/api/2fa/enable", { code }, token);

export const twoFactorDisable = (token: string, code: string) =>
  call<{ enabled: boolean }>("POST", "/api/2fa/disable", { code }, token);

export const sync = (token: string) =>
  call<{ ciphers: CipherDto[] }>("GET", "/api/sync", undefined, token);

export const createCipher = (token: string, data: string) =>
  call<CipherDto>("POST", "/api/ciphers", { data }, token);

export const updateCipher = (token: string, id: string, data: string) =>
  call<CipherDto>("PUT", `/api/ciphers/${id}`, { data }, token);

export const deleteCipher = (token: string, id: string) =>
  call<void>("DELETE", `/api/ciphers/${id}`, undefined, token);
