import { useEffect, useState } from "react";
import { type Session, type VaultItem, loginAccount, loadVault } from "@passwd/api-client";

const WEB_VAULT_URL = "http://localhost:5173";

export function App() {
  const [session, setSession] = useState<Session | null>(null);
  if (!session) return <Unlock onUnlocked={setSession} />;
  return <Vault session={session} onLock={() => setSession(null)} />;
}

function Unlock(props: { onUnlocked: (s: Session) => void }) {
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      props.onUnlocked(await loginAccount(identifier, password));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unlock failed.");
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

function Vault(props: { session: Session; onLock: () => void }) {
  const [items, setItems] = useState<VaultItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [copied, setCopied] = useState<string | null>(null);

  useEffect(() => {
    loadVault(props.session)
      .then(setItems)
      .catch((e) => setError(e instanceof Error ? e.message : "Failed to load vault."))
      .finally(() => setLoading(false));
  }, [props.session]);

  async function copy(label: string, value: string) {
    await navigator.clipboard.writeText(value);
    setCopied(label);
    setTimeout(() => setCopied(null), 1200);
  }

  const filtered = items.filter(
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
        <button className="ghost" onClick={props.onLock}>
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
          {filtered.map((item) => (
            <li key={item.id}>
              <div className="info">
                <div className="name">{item.name || "(unnamed)"}</div>
                <div className="sub">{item.username || item.url}</div>
              </div>
              <div className="actions">
                {item.username && (
                  <button className="ghost" onClick={() => copy("user", item.username)} title="Copy username">
                    User
                  </button>
                )}
                {item.password && (
                  <button className="ghost" onClick={() => copy("pass", item.password)} title="Copy password">
                    Pass
                  </button>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
      {copied && <div className="toast">Copied {copied === "user" ? "username" : "password"}</div>}
    </div>
  );
}
