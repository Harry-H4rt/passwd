import { useEffect, useMemo, useState } from "react";
import { generatePassword, type ItemFields, type VaultItem } from "@passwd/api-client";
import {
  type ItemView,
  type StateResponse,
  type ItemsResponse,
  type UnlockResponse,
  type MutationResponse,
  type PendingResponse,
  type PendingSave,
  type FillMessage,
  sendBackground,
  hostMatches,
} from "../../utils/protocol";

// Web vault URL for the "create an account" link. Override with WXT_VAULT_URL
// for production (see .env.example).
const WEB_VAULT_URL =
  (import.meta.env as Record<string, string | undefined>).WXT_VAULT_URL ?? "http://localhost:5173";

export function App() {
  const [loading, setLoading] = useState(true);
  const [locked, setLocked] = useState(true);

  useEffect(() => {
    sendBackground<StateResponse>({ type: "getState" })
      .then((s) => setLocked(s.locked))
      .finally(() => setLoading(false));
  }, []);

  if (loading)
    return (
      <Shell>
        <p className="muted center">Loading...</p>
      </Shell>
    );
  return locked ? <Unlock onUnlocked={() => setLocked(false)} /> : <Vault onLock={() => setLocked(true)} />;
}

// App shell: fixed, app-like size with a trust footer pinned to the bottom.
function Shell(props: { children: React.ReactNode; pad?: boolean }) {
  return (
    <div className="shell">
      <div className={props.pad === false ? "body" : "body padded"}>{props.children}</div>
      <footer className="trust">
        <LockMark size={13} />
        Zero-knowledge. Your keys never leave this device.
      </footer>
    </div>
  );
}

function LockMark({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="4" y="10" width="16" height="11" rx="2" />
      <path d="M8 10V7a4 4 0 0 1 8 0v3" />
    </svg>
  );
}

// Deterministic monogram avatar: a stable color per item (hashed from its host or
// name) so items are visually distinct without fetching remote favicons (which
// would leak the vault's domains).
function Avatar({ item }: { item: { name: string; url: string } }) {
  const key = (safeHost(item.url) || item.name || "?").toLowerCase();
  const initial = (item.name || safeHost(item.url) || "?").trim().charAt(0).toUpperCase() || "?";
  let h = 0;
  for (const ch of key) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  return (
    <span className="avatar" style={{ background: `hsl(${h % 360} 58% 42%)` }} aria-hidden="true">
      {initial}
    </span>
  );
}

function safeHost(url: string): string {
  if (!url) return "";
  try {
    return new URL(url.includes("://") ? url : `https://${url}`).hostname.replace(/^www\./, "");
  } catch {
    return "";
  }
}

function Unlock(props: { onUnlocked: () => void }) {
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const res = await sendBackground<UnlockResponse>({ type: "unlock", identifier, masterPassword: password });
      if (res.ok) props.onUnlocked();
      else setError(res.error || "Unlock failed.");
    } catch {
      setError("Unlock failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Shell>
      <form className="unlock" onSubmit={submit}>
        <h1 className="title">
          <LockMark /> passwd
        </h1>
        <p className="muted center tagline">Unlock your vault for this browser.</p>
        <input
          placeholder="passphrase or email"
          value={identifier}
          onChange={(e) => setIdentifier(e.target.value)}
          autoFocus
          spellCheck={false}
          autoComplete="off"
        />
        <div className="pwrow">
          <input
            type={showPw ? "text" : "password"}
            placeholder="master password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="off"
          />
          <button type="button" className="reveal" onClick={() => setShowPw((s) => !s)}>
            {showPw ? "Hide" : "Show"}
          </button>
        </div>
        {error && <div className="error">{error}</div>}
        <button className="primary" disabled={busy} type="submit">
          {busy ? "Unlocking..." : "Unlock"}
        </button>
        <a className="link" href={WEB_VAULT_URL} target="_blank" rel="noreferrer">
          No account? Create one in the web vault
        </a>
      </form>
    </Shell>
  );
}

function Vault(props: { onLock: () => void }) {
  const [items, setItems] = useState<ItemView[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [tabHost, setTabHost] = useState("");
  const [toast, setToast] = useState<string | null>(null);
  const [editing, setEditing] = useState<VaultItem | null>(null);
  const [fromPending, setFromPending] = useState(false);
  const [pending, setPending] = useState<PendingSave | null>(null);

  async function reload() {
    const res = await sendBackground<ItemsResponse>({ type: "getItems" });
    if (res.locked) return props.onLock();
    if (res.error) setError(res.error);
    else setItems(res.items ?? []);
  }

  useEffect(() => {
    reload().finally(() => setLoading(false));
    sendBackground<PendingResponse>({ type: "getPending" }).then((p) => setPending(p.pending));

    browser.tabs
      .query({ active: true, currentWindow: true })
      .then((tabs) => {
        const url = tabs[0]?.url;
        if (url) {
          try {
            setTabHost(new URL(url).hostname);
          } catch {
            /* non-web tab */
          }
        }
      })
      .catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function flash(label: string) {
    setToast(label);
    setTimeout(() => setToast(null), 1200);
  }

  async function copy(label: string, value: string) {
    await navigator.clipboard.writeText(value);
    flash(`Copied ${label}`);
  }

  async function fill(item: ItemView) {
    const tabs = await browser.tabs.query({ active: true, currentWindow: true });
    const tabId = tabs[0]?.id;
    if (tabId == null) return;
    const msg: FillMessage = { type: "fill", username: item.username, password: item.password };
    try {
      await browser.tabs.sendMessage(tabId, msg);
      flash("Filled");
      window.close();
    } catch {
      flash("No login form found");
    }
  }

  async function lock() {
    await sendBackground({ type: "lock" });
    props.onLock();
  }

  function startAdd() {
    setFromPending(false);
    setEditing({ id: "", name: "", username: "", password: "", url: "", notes: "" });
  }

  function reviewPending() {
    if (!pending) return;
    const host = safeHost(pending.url);
    setFromPending(true);
    setEditing({
      id: "",
      name: host || "New login",
      username: pending.username,
      password: pending.password,
      url: pending.url,
      notes: "",
    });
  }

  async function dismissPending() {
    setPending(null);
    await sendBackground({ type: "dismissPending" });
  }

  async function saveEditing(item: VaultItem): Promise<string | null> {
    const res = item.id
      ? await sendBackground<MutationResponse>({ type: "updateItem", item })
      : await sendBackground<MutationResponse>({ type: "addItem", fields: stripId(item) });
    if (res.locked) {
      props.onLock();
      return null;
    }
    if (res.error) return res.error;
    if (fromPending) await dismissPending();
    setEditing(null);
    setFromPending(false);
    await reload();
    flash(item.id ? "Saved" : "Added");
    return null;
  }

  async function deleteEditing(item: VaultItem): Promise<string | null> {
    const res = await sendBackground<MutationResponse>({ type: "deleteItem", id: item.id });
    if (res.locked) {
      props.onLock();
      return null;
    }
    if (res.error) return res.error;
    setEditing(null);
    await reload();
    flash("Deleted");
    return null;
  }

  // Items whose saved URL matches the current tab's domain come first.
  const sorted = useMemo(() => {
    const matches = (i: ItemView) => (tabHost ? hostMatches(i.url, tabHost) : false);
    return [...items].sort((a, b) => Number(matches(b)) - Number(matches(a)));
  }, [items, tabHost]);

  const filtered = sorted.filter(
    (i) =>
      !query ||
      i.name.toLowerCase().includes(query.toLowerCase()) ||
      i.username.toLowerCase().includes(query.toLowerCase()) ||
      i.url.toLowerCase().includes(query.toLowerCase()),
  );

  if (editing) {
    return (
      <Editor
        item={editing}
        onCancel={() => {
          setEditing(null);
          setFromPending(false);
        }}
        onSave={saveEditing}
        onDelete={deleteEditing}
      />
    );
  }

  return (
    <Shell pad={false}>
      <div className="vault">
        <header>
          <span className="brand">
            <LockMark /> passwd
          </span>
          <div className="header-actions">
            <button className="ghost" onClick={startAdd}>
              + Add
            </button>
            <button className="ghost" onClick={lock}>
              Lock
            </button>
          </div>
        </header>

        {pending && (
          <div className="pending">
            <div className="pending-text">
              Save login for <strong>{safeHost(pending.url) || "this site"}</strong>?
            </div>
            <div className="pending-actions">
              <button className="primary small" onClick={reviewPending}>
                Review &amp; save
              </button>
              <button className="ghost" onClick={dismissPending}>
                Not now
              </button>
            </div>
          </div>
        )}

        <input className="search" placeholder="Search" value={query} onChange={(e) => setQuery(e.target.value)} />

        {error && <div className="error">{error}</div>}
        <div className="list-area">
          {loading ? (
            <p className="muted">Decrypting...</p>
          ) : filtered.length === 0 ? (
            <p className="muted">
              No items yet. Use <strong>+ Add</strong> to store your first login.
            </p>
          ) : (
            <ul>
              {filtered.map((item) => {
                const match = tabHost && hostMatches(item.url, tabHost);
                return (
                  <li key={item.id} className={match ? "match" : ""}>
                    <Avatar item={item} />
                    <div className="info">
                      <div className="name">
                        {item.name || "(unnamed)"} {match && <span className="badge">this site</span>}
                      </div>
                      <div className="sub">{item.username || item.url}</div>
                    </div>
                    <div className="actions">
                      {item.password && (
                        <button className="ghost" onClick={() => fill(item)} title="Fill this page">
                          Fill
                        </button>
                      )}
                      {item.password && (
                        <button className="ghost" onClick={() => copy("password", item.password)} title="Copy password">
                          Copy
                        </button>
                      )}
                      <button className="ghost" onClick={() => setEditing(item)} title="Edit">
                        Edit
                      </button>
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </div>
      {toast && <div className="toast">{toast}</div>}
    </Shell>
  );
}

function Editor(props: {
  item: VaultItem;
  onCancel: () => void;
  onSave: (i: VaultItem) => Promise<string | null>;
  onDelete: (i: VaultItem) => Promise<string | null>;
}) {
  const [item, setItem] = useState<VaultItem>(props.item);
  const [showPw, setShowPw] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const set = (k: keyof VaultItem, v: string) => setItem((p) => ({ ...p, [k]: v }));
  const isNew = !item.id;

  async function save() {
    if (!item.name.trim() && !item.username.trim() && !item.url.trim()) {
      setError("Give the item a name, username, or URL.");
      return;
    }
    setBusy(true);
    setError(null);
    const err = await props.onSave(item);
    if (err) setError(err);
    setBusy(false);
  }

  async function del() {
    if (!confirm(`Delete "${item.name || "this item"}"?`)) return;
    setBusy(true);
    setError(null);
    const err = await props.onDelete(item);
    if (err) setError(err);
    setBusy(false);
  }

  return (
    <Shell>
      <div className="editor">
        <h1 className="title left">{isNew ? "Add item" : "Edit item"}</h1>
        <label>Name</label>
        <input value={item.name} onChange={(e) => set("name", e.target.value)} placeholder="GitHub" autoFocus />
        <label>URL</label>
        <input value={item.url} onChange={(e) => set("url", e.target.value)} placeholder="https://github.com" />
        <label>Username</label>
        <input value={item.username} onChange={(e) => set("username", e.target.value)} placeholder="you@example.com" />
        <label>Password</label>
        <div className="pwrow">
          <input
            type={showPw ? "text" : "password"}
            value={item.password}
            onChange={(e) => set("password", e.target.value)}
          />
          <button type="button" className="reveal" onClick={() => setShowPw((s) => !s)}>
            {showPw ? "Hide" : "Show"}
          </button>
        </div>
        <button type="button" className="ghost full" onClick={() => set("password", generatePassword())}>
          Generate password
        </button>
        <label>Notes</label>
        <textarea value={item.notes} onChange={(e) => set("notes", e.target.value)} rows={2} />

        {error && <div className="error">{error}</div>}

        <div className="editor-actions">
          <button className="ghost" onClick={props.onCancel} disabled={busy}>
            Cancel
          </button>
          <button className="primary" onClick={save} disabled={busy}>
            {busy ? "Saving..." : "Save"}
          </button>
        </div>
        {!isNew && (
          <button className="ghost danger full" onClick={del} disabled={busy}>
            Delete item
          </button>
        )}
      </div>
    </Shell>
  );
}

function stripId(item: VaultItem): ItemFields {
  const { id: _id, ...fields } = item;
  return fields;
}
