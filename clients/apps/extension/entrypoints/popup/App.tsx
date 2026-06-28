import { useEffect, useMemo, useState } from "react";
import {
  type ItemView,
  type StateResponse,
  type ItemsResponse,
  type UnlockResponse,
  type FillMessage,
  sendBackground,
  hostMatches,
} from "../../utils/protocol";

const WEB_VAULT_URL = "http://localhost:5173";

export function App() {
  const [loading, setLoading] = useState(true);
  const [locked, setLocked] = useState(true);

  useEffect(() => {
    sendBackground<StateResponse>({ type: "getState" })
      .then((s) => setLocked(s.locked))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="vault"><p className="muted">…</p></div>;
  return locked ? <Unlock onUnlocked={() => setLocked(false)} /> : <Vault onLock={() => setLocked(true)} />;
}

function Unlock(props: { onUnlocked: () => void }) {
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
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
    <form className="unlock" onSubmit={submit}>
      <h1>
        passwd <span>🔒</span>
      </h1>
      <input
        placeholder="passphrase or email"
        value={identifier}
        onChange={(e) => setIdentifier(e.target.value)}
        autoFocus
        spellCheck={false}
        autoComplete="off"
      />
      <input
        type="password"
        placeholder="master password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        autoComplete="off"
      />
      {error && <div className="error">{error}</div>}
      <button className="primary" disabled={busy} type="submit">
        {busy ? "Unlocking…" : "Unlock"}
      </button>
      <a className="link" href={WEB_VAULT_URL} target="_blank" rel="noreferrer">
        No account? Create one in the web vault →
      </a>
    </form>
  );
}

function Vault(props: { onLock: () => void }) {
  const [items, setItems] = useState<ItemView[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [tabHost, setTabHost] = useState("");
  const [toast, setToast] = useState<string | null>(null);

  useEffect(() => {
    sendBackground<ItemsResponse>({ type: "getItems" })
      .then((res) => {
        if (res.locked) return props.onLock();
        if (res.error) setError(res.error);
        else setItems(res.items ?? []);
      })
      .finally(() => setLoading(false));

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
  }, []);

  async function flash(label: string) {
    setToast(label);
    setTimeout(() => setToast(null), 1200);
  }

  async function copy(label: string, value: string) {
    await navigator.clipboard.writeText(value);
    void flash(`Copied ${label}`);
  }

  async function fill(item: ItemView) {
    const tabs = await browser.tabs.query({ active: true, currentWindow: true });
    const tabId = tabs[0]?.id;
    if (tabId == null) return;
    const msg: FillMessage = { type: "fill", username: item.username, password: item.password };
    try {
      await browser.tabs.sendMessage(tabId, msg);
      void flash("Filled");
      window.close();
    } catch {
      void flash("No login form found");
    }
  }

  async function lock() {
    await sendBackground({ type: "lock" });
    props.onLock();
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

  return (
    <div className="vault">
      <header>
        <span className="brand">passwd 🔒</span>
        <button className="ghost" onClick={lock}>
          Lock
        </button>
      </header>
      <input className="search" placeholder="Search…" value={query} onChange={(e) => setQuery(e.target.value)} />

      {error && <div className="error">{error}</div>}
      {loading ? (
        <p className="muted">Decrypting…</p>
      ) : filtered.length === 0 ? (
        <p className="muted">
          No items. <a href={WEB_VAULT_URL} target="_blank" rel="noreferrer">Open the web vault</a> to add some.
        </p>
      ) : (
        <ul>
          {filtered.map((item) => {
            const match = tabHost && hostMatches(item.url, tabHost);
            return (
              <li key={item.id} className={match ? "match" : ""}>
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
                  {item.username && (
                    <button className="ghost" onClick={() => copy("username", item.username)}>
                      User
                    </button>
                  )}
                  {item.password && (
                    <button className="ghost" onClick={() => copy("password", item.password)}>
                      Pass
                    </button>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      )}
      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}
