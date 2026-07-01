// Password health and breach checks. Privacy is the constraint here:
//
//   - Weakness and reuse are computed entirely on the already-decrypted vault,
//     in this tab. No network, nothing leaves the device.
//   - The breach check uses the HaveIBeenPwned k-anonymity range API: we SHA-1
//     the password locally and send only the first 5 hex characters of that
//     hash. HIBP returns every suffix sharing that prefix (hundreds of them) and
//     we match the rest locally, so neither the password nor its full hash ever
//     leaves the browser. The passwd backend is never involved.

import type { VaultItem } from "@passwd/api-client";

// Local-only strength heuristic. Returns a short reason if the password is weak,
// or null if it looks fine. Empty passwords are "no password", not weak.
export function passwordWeakness(pw: string): string | null {
  if (!pw) return null;
  if (pw.length < 10) return "Short (under 10 characters)";
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(pw)).length;
  if (pw.length < 14 && classes < 3) return "Low complexity";
  return null;
}

// Item ids whose password is shared by more than one item (reuse), computed
// locally. Empty passwords are ignored.
export function reusedItemIds(items: VaultItem[]): Set<string> {
  const byPassword = new Map<string, string[]>();
  for (const it of items) {
    if (!it.password) continue;
    const ids = byPassword.get(it.password) ?? [];
    ids.push(it.id);
    byPassword.set(it.password, ids);
  }
  const reused = new Set<string>();
  for (const ids of byPassword.values()) {
    if (ids.length > 1) ids.forEach((id) => reused.add(id));
  }
  return reused;
}

// Uppercase hex SHA-1 of a string, via Web Crypto (no network).
async function sha1Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

// Times a password appears in known breaches (0 = not found), via HIBP
// k-anonymity. Only the 5-char SHA-1 prefix is sent; "Add-Padding" hides the
// true size of the returned suffix set from a network observer.
export async function breachCount(pw: string): Promise<number> {
  const hash = await sha1Hex(pw);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  const url = `https://api.pwnedpasswords.com/range/${prefix}`;
  let res: Response;
  try {
    res = await fetch(url, { headers: { "Add-Padding": "true" } });
  } catch {
    // A browser may reject the custom-header CORS preflight; fall back to a
    // plain request. Still k-anonymous (only the 5-char prefix is sent); only
    // the response-size padding is lost.
    res = await fetch(url);
  }
  if (!res.ok) throw new Error(`breach service returned ${res.status}`);
  const text = await res.text();
  for (const line of text.split("\n")) {
    const idx = line.indexOf(":");
    if (idx === -1) continue;
    if (line.slice(0, idx) === suffix) return parseInt(line.slice(idx + 1), 10) || 0;
  }
  return 0;
}

// Checks the vault's distinct passwords against HIBP, one request per unique
// password (deduped to minimise external calls), and returns a map from item id
// to breach count for the breached ones. Failures for individual passwords are
// swallowed so one hiccup doesn't sink the whole report.
export async function breachedItemIds(items: VaultItem[]): Promise<Map<string, number>> {
  const unique = new Map<string, string[]>(); // password -> item ids
  for (const it of items) {
    if (!it.password) continue;
    const ids = unique.get(it.password) ?? [];
    ids.push(it.id);
    unique.set(it.password, ids);
  }
  const out = new Map<string, number>();
  for (const [pw, ids] of unique) {
    try {
      const n = await breachCount(pw);
      if (n > 0) ids.forEach((id) => out.set(id, n));
    } catch {
      // leave these items unmarked rather than failing the whole check
    }
  }
  return out;
}
