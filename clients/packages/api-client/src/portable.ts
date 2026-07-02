// Vault import/export serialization. Pure functions (no network, no crypto) so
// they are easy to test. The web app pairs these with encryptBackup/decryptBackup
// from @passwd/crypto for the encrypted-backup path.

import { normalizeItemFields, type ItemFields } from "./session.js";

// Flat string columns for CSV (logins only carry these; cards/identities need
// JSON). `favorite` is boolean and handled separately.
const FIELDS = ["name", "url", "username", "password", "totp", "notes", "folder"] as const;
type Field = (typeof FIELDS)[number];

export const EXPORT_FORMAT = "passwd-export";
// v1 had only flat login fields; v2 adds type/totp/card/identity/fields. Both
// import fine: normalizeItemFields blanks whatever a file doesn't carry.
export const EXPORT_VERSION = 2;

interface PlaintextExport {
  format: typeof EXPORT_FORMAT;
  version: number;
  items: ItemFields[];
}

// --- Export -----------------------------------------------------------------

export function toPlaintextJSON(items: ItemFields[]): string {
  const payload: PlaintextExport = {
    format: EXPORT_FORMAT,
    version: EXPORT_VERSION,
    items: items.map((i) => normalizeItemFields(i as unknown as Record<string, unknown>)),
  };
  return JSON.stringify(payload, null, 2);
}

export function toCSV(items: ItemFields[]): string {
  const rows = [[...FIELDS, "favorite"].join(",")];
  for (const it of items)
    rows.push([...FIELDS.map((f) => csvEscape(it[f] ?? "")), it.favorite ? "1" : ""].join(","));
  return rows.join("\r\n");
}

function csvEscape(v: string): string {
  return /[",\r\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
}

// --- Import -----------------------------------------------------------------

// Parse an exported file into items, auto-detecting passwd/generic JSON vs CSV.
// Encrypted backups must be decrypted first (see @passwd/crypto). Throws on input
// that yields no usable items.
export function parseVaultImport(text: string): ItemFields[] {
  const trimmed = text.trim();
  if (!trimmed) throw new Error("the file is empty");
  const items = trimmed[0] === "{" || trimmed[0] === "[" ? parseJSON(trimmed) : parseCSV(trimmed);
  if (items.length === 0) throw new Error("no items found in the file");
  return items;
}

function parseJSON(text: string): ItemFields[] {
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error("the file is not valid JSON");
  }
  const arr = Array.isArray(data)
    ? data
    : Array.isArray((data as { items?: unknown }).items)
      ? (data as { items: unknown[] }).items
      : null;
  if (!arr) throw new Error("unrecognized JSON: expected an array of items");
  return arr.map((row) => normalize(row as Record<string, unknown>)).filter(nonEmpty);
}

function parseCSV(text: string): ItemFields[] {
  const rows = csvRows(text);
  const header = rows.shift();
  if (!header) return [];
  const cols = header.map((h) => {
    const lower = h.trim().toLowerCase();
    return ALIASES[lower] ?? (FAVORITE_KEYS.includes(lower) ? ("favorite" as const) : null);
  });
  return rows
    .map((cells) => {
      const obj: Record<string, unknown> = {};
      cols.forEach((field, i) => {
        if (field && obj[field] === undefined) obj[field] = cells[i] ?? "";
      });
      return normalize(obj);
    })
    .filter(nonEmpty);
}

// Common column names across managers (Bitwarden, Chrome, generic) -> our fields.
const ALIASES: Record<string, Field> = {
  name: "name",
  title: "name",
  item: "name",
  url: "url",
  uri: "url",
  login_uri: "url",
  website: "url",
  site: "url",
  username: "username",
  user: "username",
  "user name": "username",
  login: "username",
  login_username: "username",
  email: "username",
  password: "password",
  pass: "password",
  login_password: "password",
  notes: "notes",
  note: "notes",
  comment: "notes",
  comments: "notes",
  totp: "totp",
  otp: "totp",
  login_totp: "totp",
  folder: "folder",
  group: "folder",
  grouping: "folder",
};

// Truthy favorite spellings across managers' CSVs.
const FAVORITE_KEYS = ["favorite", "favourite", "fav"];

function normalize(row: Record<string, unknown>): ItemFields {
  // Map foreign column names onto our flat fields and carry the structured
  // keys from passwd's own JSON exports; anything else (folders, colors, ...)
  // is dropped rather than smuggled into the vault.
  const flat: Record<string, unknown> = {};
  for (const k of ["type", "card", "identity", "fields"] as const) {
    if (row[k] !== undefined) flat[k] = row[k];
  }
  for (const [key, value] of Object.entries(row)) {
    const lower = key.trim().toLowerCase();
    if (FAVORITE_KEYS.includes(lower)) {
      flat.favorite = value;
      continue;
    }
    const field = (FIELDS as readonly string[]).includes(key) ? (key as Field) : ALIASES[lower];
    if (field && !flat[field]) flat[field] = value == null ? "" : String(value);
  }
  return normalizeItemFields(flat);
}

function nonEmpty(i: ItemFields): boolean {
  return Boolean(
    i.name ||
      i.username ||
      i.password ||
      i.url ||
      i.notes ||
      i.totp ||
      i.card.number ||
      i.identity.fullName ||
      i.identity.email ||
      i.fields.length,
  );
}

// Minimal RFC 4180 parser: handles quoted fields with embedded commas, quotes
// ("" escape), and CR/LF. Returns rows of string cells, skipping blank lines.
function csvRows(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let quoted = false;
  const src = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  for (let i = 0; i < src.length; i++) {
    const ch = src[i]!;
    if (quoted) {
      if (ch === '"') {
        if (src[i + 1] === '"') {
          cell += '"';
          i++;
        } else {
          quoted = false;
        }
      } else {
        cell += ch;
      }
    } else if (ch === '"') {
      quoted = true;
    } else if (ch === ",") {
      row.push(cell);
      cell = "";
    } else if (ch === "\n") {
      row.push(cell);
      if (row.some((c) => c !== "")) rows.push(row);
      row = [];
      cell = "";
    } else {
      cell += ch;
    }
  }
  if (cell !== "" || row.length) {
    row.push(cell);
    if (row.some((c) => c !== "")) rows.push(row);
  }
  return rows;
}
