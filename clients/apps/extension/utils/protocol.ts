// Message protocol between the popup, the background service worker, and content
// scripts. The background worker is the only place that holds the unlocked
// session (user key); the popup talks to it over messages.

import type { VaultItem } from "@passwd/api-client";

export type ItemView = VaultItem;

// popup -> background
export type BgRequest =
  | { type: "getState" }
  | { type: "unlock"; identifier: string; masterPassword: string }
  | { type: "lock" }
  | { type: "getItems" };

export interface StateResponse {
  locked: boolean;
  identifier?: string;
}

export interface ItemsResponse {
  locked?: boolean;
  items?: ItemView[];
  error?: string;
}

export interface UnlockResponse {
  ok?: boolean;
  error?: string;
}

// popup -> content script (active tab)
export interface FillMessage {
  type: "fill";
  username: string;
  password: string;
}

export function sendBackground<T = unknown>(msg: BgRequest): Promise<T> {
  return browser.runtime.sendMessage(msg) as Promise<T>;
}

// Loose host comparison for autofill domain matching: equal hostnames, or one is
// a subdomain of the other after stripping a leading "www." (e.g. an item saved
// for github.com matches www.github.com). Anti-phishing: never fuzzy-match across
// different registrable domains.
export function hostMatches(itemUrl: string, pageHost: string): boolean {
  const itemHost = safeHost(itemUrl);
  if (!itemHost || !pageHost) return false;
  const a = itemHost.replace(/^www\./, "");
  const b = pageHost.replace(/^www\./, "");
  return a === b || a.endsWith("." + b) || b.endsWith("." + a);
}

function safeHost(url: string): string {
  try {
    return new URL(url.includes("://") ? url : `https://${url}`).hostname.toLowerCase();
  } catch {
    return "";
  }
}
