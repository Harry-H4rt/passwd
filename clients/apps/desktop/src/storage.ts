// The desktop data layer: bridges the pure @passwd/crypto vault functions to the
// local filesystem via Tauri. All disk access is the app's own read_vault/
// write_vault commands (see src-tauri/src/lib.rs) on a path the user picked in a
// native dialog — there is no network and no broad filesystem scope.

import { invoke } from "@tauri-apps/api/core";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
import {
  createVault,
  openVault,
  saveVault,
  changeMasterPassword,
  type VaultState,
} from "@passwd/crypto";
import type { VaultItem } from "./types";

// An unlocked vault held in memory. `state.userKey` is sensitive and is dropped
// when the app locks.
export interface DesktopVault {
  path: string;
  state: VaultState;
  items: VaultItem[];
}

export interface RecentVault {
  path: string;
  name: string; // basename, for display
  openedAt: number;
}

const PAYLOAD_VERSION = 1;
interface Payload {
  version: number;
  items: VaultItem[];
}

function encodePayload(items: VaultItem[]): string {
  return JSON.stringify({ version: PAYLOAD_VERSION, items } satisfies Payload);
}

function decodePayload(payload: string): VaultItem[] {
  const p = JSON.parse(payload) as Payload;
  return Array.isArray(p.items) ? p.items : [];
}

export function basename(path: string): string {
  return path.split(/[\\/]/).pop() || path;
}

// --- Tauri command bridges --------------------------------------------------

const readFile = (path: string) => invoke<string>("read_vault", { path });
const writeFile = (path: string, contents: string) => invoke<void>("write_vault", { path, contents });

// --- native file dialogs ----------------------------------------------------

const VAULT_FILTER = [{ name: "passwd vault", extensions: ["passwd"] }];

export async function pickVaultToOpen(): Promise<string | null> {
  const res = await openDialog({ multiple: false, directory: false, filters: VAULT_FILTER });
  return typeof res === "string" ? res : null;
}

export async function pickVaultToCreate(): Promise<string | null> {
  const res = await saveDialog({ defaultPath: "vault.passwd", filters: VAULT_FILTER });
  return res ?? null;
}

// --- high-level vault operations --------------------------------------------

export async function createNewVault(path: string, masterPassword: string): Promise<DesktopVault> {
  const { file, state } = await createVault(masterPassword, encodePayload([]));
  await writeFile(path, file);
  return { path, state, items: [] };
}

export async function openExistingVault(path: string, masterPassword: string): Promise<DesktopVault> {
  const fileText = await readFile(path);
  const { state, payload } = await openVault(fileText, masterPassword);
  return { path, state, items: decodePayload(payload) };
}

// Re-encrypt the current items and write the file. Fast (no KDF).
export async function persist(v: DesktopVault): Promise<void> {
  const file = await saveVault(v.state, encodePayload(v.items));
  await writeFile(v.path, file);
}

// Change the master password (re-wraps the same user key) and write the file.
export async function rekey(v: DesktopVault, newPassword: string): Promise<DesktopVault> {
  const { file, state } = await changeMasterPassword(v.state, newPassword, encodePayload(v.items));
  await writeFile(v.path, file);
  return { ...v, state };
}

// --- recent vaults (paths only, never contents; clearable) ------------------

const RECENTS_MAX = 8;

export async function readRecents(): Promise<RecentVault[]> {
  try {
    const raw = await invoke<string>("read_recents");
    const list = JSON.parse(raw) as RecentVault[];
    return Array.isArray(list) ? list : [];
  } catch {
    return [];
  }
}

export async function rememberRecent(path: string): Promise<void> {
  const list = await readRecents();
  const next = [
    { path, name: basename(path), openedAt: Date.now() },
    ...list.filter((r) => r.path !== path),
  ].slice(0, RECENTS_MAX);
  await invoke<void>("write_recents", { contents: JSON.stringify(next) });
}

export async function clearRecents(): Promise<void> {
  await invoke<void>("write_recents", { contents: "[]" });
}
