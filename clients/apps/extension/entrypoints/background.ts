import { configureApi, loginAccount, loadVault, type Session } from "@passwd/api-client";
import type { BgRequest, StateResponse, ItemsResponse, UnlockResponse } from "../utils/protocol";

// The background worker owns the unlocked session. It is kept in
// chrome.storage.session (memory-only: never written to disk, cleared when the
// browser closes), so it survives the service worker sleeping/waking but is
// dropped on browser exit. An idle timer (chrome.alarms) locks it sooner.

const API_BASE = "http://localhost:8080";
const IDLE_MS = 15 * 60 * 1000;
const LOCK_ALARM = "passwd-lock";

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

      default:
        return undefined;
    }
  });
});
