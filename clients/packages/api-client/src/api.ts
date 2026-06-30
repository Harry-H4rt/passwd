// Thin typed client for the passwd backend. Transport only. It sends/receives
// the ciphertext produced by @passwd/crypto and never handles plaintext secrets.
//
// The base URL is configurable: the web vault leaves it "" (same-origin, via the
// Vite dev proxy / co-hosted in prod); the browser extension points it at the
// backend host (which it lists in host_permissions).

import type { KdfParams } from "@passwd/crypto";
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from "@simplewebauthn/browser";

export type Kdf = KdfParams;

export interface LoginResult {
  accessToken: string;
  refreshToken: string;
  protectedUserKey: string;
  protectedPrivateKey?: string;
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
  publicKey: string;
  protectedPrivateKey: string;
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
// `methods` lists the enrolled factors ("webauthn", "totp") so the UI can offer a
// choice.
export type LoginOutcome =
  | (LoginResult & { twoFactorRequired?: false })
  | { twoFactorRequired: true; methods: string[] };

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
  if (res.status === 401 && json.twoFactorRequired) {
    return { twoFactorRequired: true, methods: json.methods ?? [] };
  }
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

// --- account recovery -------------------------------------------------------
// Recovery code enrollment (authenticated) and the forgot-password flow
// (challenge → complete, no token). The server stores only the recovery-wrapped
// key + a verifier; the recovery code itself never leaves the device.

export const recoveryStatus = (token: string) =>
  call<{ enabled: boolean }>("GET", "/api/recovery", undefined, token);

export const recoveryEnable = (
  token: string,
  recoveryProtectedUserKey: string,
  recoveryAuthHash: string,
) =>
  call<void>("POST", "/api/recovery/enable", { recoveryProtectedUserKey, recoveryAuthHash }, token);

export const recoveryDisable = (token: string) =>
  call<void>("POST", "/api/recovery/disable", undefined, token);

export const recoveryChallenge = (identifier: string) =>
  call<{ recoveryProtectedUserKey: string; kdf: Kdf }>(
    "POST", "/api/auth/recovery/challenge", { identifier });

export const recoveryComplete = (params: {
  identifier: string;
  recoveryAuthHash: string;
  masterPasswordHash: string;
  protectedUserKey: string;
  kdf: Kdf;
}) => call<LoginResult>("POST", "/api/auth/recovery/complete", params);

// --- passkeys (WebAuthn) ----------------------------------------------------
// The server returns/accepts standard WebAuthn JSON; the browser ceremony
// (navigator.credentials) lives in session.ts via @simplewebauthn/browser.

export interface WebAuthnCredentialSummary {
  id: string;
  name: string;
  createdAt: string;
}

export const webauthnCredentials = (token: string) =>
  call<{ credentials: WebAuthnCredentialSummary[] }>(
    "GET", "/api/2fa/webauthn/credentials", undefined, token);

export const webauthnDeleteCredential = (token: string, id: string) =>
  call<{ deleted: boolean }>("DELETE", `/api/2fa/webauthn/credentials/${id}`, undefined, token);

export const webauthnRegisterBegin = (token: string) =>
  call<{ sessionId: string; options: { publicKey: PublicKeyCredentialCreationOptionsJSON } }>(
    "POST", "/api/2fa/webauthn/register/begin", {}, token);

export const webauthnRegisterFinish = (
  token: string,
  sessionId: string,
  name: string,
  credential: RegistrationResponseJSON,
) =>
  call<{ id: string; name: string }>(
    "POST", "/api/2fa/webauthn/register/finish", { sessionId, name, credential }, token);

export const webauthnLoginBegin = (identifier: string, masterPasswordHash: string) =>
  call<{ sessionId: string; options: { publicKey: PublicKeyCredentialRequestOptionsJSON } }>(
    "POST", "/api/auth/webauthn/begin", { identifier, masterPasswordHash });

export const webauthnLoginFinish = (
  identifier: string,
  masterPasswordHash: string,
  sessionId: string,
  credential: AuthenticationResponseJSON,
) =>
  call<LoginResult>(
    "POST", "/api/auth/webauthn/finish", { identifier, masterPasswordHash, sessionId, credential });

export interface AuditEvent {
  event: string;
  detail?: string;
  createdAt: string;
}

export const auditLog = (token: string) =>
  call<{ events: AuditEvent[] }>("GET", "/api/audit", undefined, token);

// --- sharing ----------------------------------------------------------------

export interface ShareDto {
  id: string;
  wrappedKey: string;
  data: string;
  createdAt: string;
}

export const lookupPublicKey = (token: string, identifier: string) =>
  call<{ publicKey: string }>(
    "GET", `/api/users/public-key?identifier=${encodeURIComponent(identifier)}`, undefined, token);

export const createShare = (
  token: string,
  share: { recipientIdentifier: string; wrappedKey: string; data: string },
) => call<{ id: string }>("POST", "/api/shares", share, token);

export const listShares = (token: string) =>
  call<{ shares: ShareDto[] }>("GET", "/api/shares", undefined, token);

export const deleteShare = (token: string, id: string) =>
  call<void>("DELETE", `/api/shares/${id}`, undefined, token);

export const sync = (token: string) =>
  call<{ ciphers: CipherDto[] }>("GET", "/api/sync", undefined, token);

export const createCipher = (token: string, data: string) =>
  call<CipherDto>("POST", "/api/ciphers", { data }, token);

export const updateCipher = (token: string, id: string, data: string) =>
  call<CipherDto>("PUT", `/api/ciphers/${id}`, { data }, token);

export const deleteCipher = (token: string, id: string) =>
  call<void>("DELETE", `/api/ciphers/${id}`, undefined, token);
