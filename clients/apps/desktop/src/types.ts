// A decrypted vault entry. `id` is a local random id (no server). The whole list
// is encrypted as one payload inside the vault file.
export interface VaultItem {
  id: string;
  name: string;
  username: string;
  password: string;
  url: string;
  notes: string;
}

export type ItemFields = Omit<VaultItem, "id">;

export function blankItem(): VaultItem {
  return { id: "", name: "", username: "", password: "", url: "", notes: "" };
}

export function newItemId(): string {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

// Strong password generator for the "generate" button (mirrors the web vault).
export function generatePassword(length = 20): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+";
  const out: string[] = [];
  const buf = new Uint32Array(length);
  crypto.getRandomValues(buf);
  for (let i = 0; i < length; i++) out.push(alphabet[buf[i]! % alphabet.length]!);
  return out.join("");
}
