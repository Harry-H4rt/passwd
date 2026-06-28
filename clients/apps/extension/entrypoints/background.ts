import {
  configureApi,
  loginAccount,
  loadVault,
  addItem,
  saveItem,
  removeItem,
  type Session,
} from "@passwd/api-client";
import type {
  BgRequest,
  StateResponse,
  ItemsResponse,
  UnlockResponse,
  MutationResponse,
  PendingResponse,
  PendingSave,
} from "../utils/protocol";

// The background worker owns the unlocked session. It is kept in
// chrome.storage.session (memory-only: never written to disk, cleared when the
// browser closes), so it survives the service worker sleeping/waking but is
// dropped on browser exit. An idle timer (chrome.alarms) locks it sooner.

// Build-time API origin (see clients/apps/extension/.env.example). Must match the
// manifest host_permissions origin in wxt.config.ts.
const API_BASE = (import.meta.env as Record<string, string | undefined>).WXT_API_BASE ?? "http://localhost:8080";
const IDLE_MS = 15 * 60 * 1000;
const LOCK_ALARM = "passwd-lock";
// A captured login is only offered to save for a short window, so a stale
// password never lingers in session memory.
const PENDING_TTL_MS = 5 * 60 * 1000;

configureApi({ baseUrl: API_BASE });

interface StoredSession {
  identifier: string;
  accessToken: string;
  refreshToken: string;
  userKeyB64: string;
  lockAt: number;
}

const b64encode = (u: Uint8Array) => btoa(String.fromCharCode(...u));
const b64decode = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function readStored(): Promise<StoredSession | null> {
  const got = (await browser.storage.session.get("session")) as { session?: StoredSession };
  const s = got.session;
  if (!s) return null;
  if (Date.now() > s.lockAt) {
    await clearStored();
    return null;
  }
  return s;
}

async function writeStored(s: StoredSession): Promise<void> {
  await browser.storage.session.set({ session: s });
  await browser.alarms.create(LOCK_ALARM, { when: s.lockAt });
}

async function clearStored(): Promise<void> {
  await browser.storage.session.remove("session");
  await browser.alarms.clear(LOCK_ALARM);
}

function toSession(s: StoredSession): Session {
  return {
    identifier: s.identifier,
    accessToken: s.accessToken,
    refreshToken: s.refreshToken,
    userKey: b64decode(s.userKeyB64),
  };
}

// Extend the idle deadline on activity.
async function touch(s: StoredSession): Promise<void> {
  s.lockAt = Date.now() + IDLE_MS;
  await writeStored(s);
}

// --- pending save (captured login awaiting the user's decision) -------------

interface StoredPending extends PendingSave {
  capturedAt: number;
}

async function readPending(): Promise<PendingSave | null> {
  const got = (await browser.storage.session.get("pending")) as { pending?: StoredPending };
  const p = got.pending;
  if (!p) return null;
  if (Date.now() - p.capturedAt > PENDING_TTL_MS) {
    await browser.storage.session.remove("pending");
    return null;
  }
  return { url: p.url, username: p.username, password: p.password };
}

export default defineBackground(() => {
  browser.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === LOCK_ALARM) void clearStored();
  });

  browser.runtime.onMessage.addListener((message: unknown): Promise<unknown> | undefined => {
    const msg = message as BgRequest;
    switch (msg.type) {
      case "getState":
        return (async (): Promise<StateResponse> => {
          const s = await readStored();
          return s ? { locked: false, identifier: s.identifier } : { locked: true };
        })();

      case "unlock":
        return (async (): Promise<UnlockResponse> => {
          try {
            const sess = await loginAccount(msg.identifier, msg.masterPassword);
            await writeStored({
              identifier: sess.identifier,
              accessToken: sess.accessToken,
              refreshToken: sess.refreshToken,
              userKeyB64: b64encode(sess.userKey),
              lockAt: Date.now() + IDLE_MS,
            });
            return { ok: true };
          } catch (e) {
            return { error: e instanceof Error ? e.message : "unlock failed" };
          }
        })();

      case "lock":
        return (async () => {
          await clearStored();
          return { ok: true };
        })();

      case "getItems":
        return (async (): Promise<ItemsResponse> => {
          const s = await readStored();
          if (!s) return { locked: true };
          try {
            await touch(s);
            return { items: await loadVault(toSession(s)) };
          } catch (e) {
            return { error: e instanceof Error ? e.message : "failed to load vault" };
          }
        })();

      case "addItem":
        return (async (): Promise<MutationResponse> => {
          const s = await readStored();
          if (!s) return { locked: true };
          try {
            await touch(s);
            return { ok: true, item: await addItem(toSession(s), msg.fields) };
          } catch (e) {
            return { error: e instanceof Error ? e.message : "failed to add item" };
          }
        })();

      case "updateItem":
        return (async (): Promise<MutationResponse> => {
          const s = await readStored();
          if (!s) return { locked: true };
          try {
            await touch(s);
            await saveItem(toSession(s), msg.item);
            return { ok: true };
          } catch (e) {
            return { error: e instanceof Error ? e.message : "failed to save item" };
          }
        })();

      case "deleteItem":
        return (async (): Promise<MutationResponse> => {
          const s = await readStored();
          if (!s) return { locked: true };
          try {
            await touch(s);
            await removeItem(toSession(s), msg.id);
            return { ok: true };
          } catch (e) {
            return { error: e instanceof Error ? e.message : "failed to delete item" };
          }
        })();

      case "captureLogin":
        return (async (): Promise<{ ok: true }> => {
          // Store the latest captured login (memory-only) for the popup to offer.
          if (msg.password) {
            const pending: StoredPending = {
              url: msg.url,
              username: msg.username,
              password: msg.password,
              capturedAt: Date.now(),
            };
            await browser.storage.session.set({ pending });
          }
          return { ok: true };
        })();

      case "getPending":
        return (async (): Promise<PendingResponse> => ({ pending: await readPending() }))();

      case "dismissPending":
        return (async (): Promise<{ ok: true }> => {
          await browser.storage.session.remove("pending");
          return { ok: true };
        })();

      default:
        return undefined;
    }
  });
});
