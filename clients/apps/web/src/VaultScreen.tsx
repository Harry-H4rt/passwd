import { useEffect, useState } from "react";
import {
  type Session,
  type VaultItem,
  blankFields,
  loadVault,
  addItem,
  saveItem,
  removeItem,
  generatePassword,
  getTwoFactorStatus,
  setupTwoFactor,
  enableTwoFactor,
  disableTwoFactor,
} from "@passwd/api-client";

export function VaultScreen(props: {
  session: Session;
  recovery: string | null;
  onDismissRecovery: () => void;
  onLock: () => void;
}) {
  const { session } = props;
  const [items, setItems] = useState<VaultItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<VaultItem | null>(null);
  const [query, setQuery] = useState("");
  const [show2fa, setShow2fa] = useState(false);

  async function reload() {
    setLoading(true);
    setError(null);
    try {
      setItems(await loadVault(session));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load vault.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleSave(item: VaultItem) {
    try {
      if (item.id) await saveItem(session, item);
      else await addItem(session, stripId(item));
      setEditing(null);
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Save failed.");
    }
  }

  async function handleDelete(item: VaultItem) {
    if (!confirm(`Delete "${item.name || "this item"}"?`)) return;
    try {
      await removeItem(session, item.id);
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Delete failed.");
    }
  }

  const filtered = items.filter(
    (i) =>
      !query ||
      i.name.toLowerCase().includes(query.toLowerCase()) ||
      i.username.toLowerCase().includes(query.toLowerCase()) ||
      i.url.toLowerCase().includes(query.toLowerCase()),
  );

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          passwd <span className="lock">🔒</span>
        </div>
        <div className="account" title={session.identifier}>
          {session.identifier}
        </div>
        <button className="ghost" onClick={() => setShow2fa(true)}>
          2FA
        </button>
        <button className="ghost" onClick={props.onLock}>
          Lock
        </button>
      </header>

      {props.recovery && (
        <div className="recovery">
          <strong>Save your recovery passphrase.</strong> This is the only way back into your account —
          there is no reset. Store it somewhere safe (not in this vault).
          <pre>{props.recovery}</pre>
          <button className="ghost" onClick={() => navigator.clipboard?.writeText(props.recovery!)}>
            Copy
          </button>
          <button className="ghost" onClick={props.onDismissRecovery}>
            I've saved it
          </button>
        </div>
      )}

      <div className="toolbar">
        <input className="search" placeholder="Search…" value={query} onChange={(e) => setQuery(e.target.value)} />
        <button className="primary" onClick={() => setEditing({ id: "", ...blankFields() })}>
          + Add item
        </button>
      </div>

      {error && <div className="error banner">{error}</div>}

      {loading ? (
        <p className="muted center-text">Decrypting vault…</p>
      ) : filtered.length === 0 ? (
        <p className="muted center-text">No items yet. Click “Add item” to store your first password.</p>
      ) : (
        <ul className="items">
          {filtered.map((item) => (
            <li key={item.id} className="item">
              <div className="item-main">
                <div className="item-name">{item.name || "(unnamed)"}</div>
                <div className="item-sub">{item.username || item.url}</div>
              </div>
              <div className="item-actions">
                {item.password && (
                  <button className="ghost" onClick={() => navigator.clipboard?.writeText(item.password)}>
                    Copy password
                  </button>
                )}
                <button className="ghost" onClick={() => setEditing(item)}>
                  Edit
                </button>
                <button className="ghost danger" onClick={() => handleDelete(item)}>
                  Delete
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}

      {editing && <ItemEditor item={editing} onCancel={() => setEditing(null)} onSave={handleSave} />}
      {show2fa && <TwoFactor session={session} onClose={() => setShow2fa(false)} />}
    </div>
  );
}

function stripId(item: VaultItem) {
  const { id: _id, ...fields } = item;
  return fields;
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : "Something went wrong.";
}

function TwoFactor(props: { session: Session; onClose: () => void }) {
  const [loading, setLoading] = useState(true);
  const [enabled, setEnabled] = useState(false);
  const [setup, setSetup] = useState<{ secret: string; otpauthUri: string } | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    getTwoFactorStatus(props.session)
      .then((s) => setEnabled(s.enabled))
      .catch((e) => setError(errMsg(e)))
      .finally(() => setLoading(false));
  }, [props.session]);

  async function run(fn: () => Promise<void>) {
    setError(null);
    setBusy(true);
    try {
      await fn();
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" onClick={props.onClose}>
      <div className="card modal" onClick={(e) => e.stopPropagation()}>
        <h2>Two-factor authentication</h2>
        {loading ? (
          <p className="muted">Loading…</p>
        ) : enabled ? (
          <>
            <p className="muted">
              2FA is <strong>enabled</strong>. Enter a current code to turn it off.
            </p>
            <input value={code} onChange={(e) => setCode(e.target.value)} placeholder="6-digit code" inputMode="numeric" autoFocus />
            {error && <div className="error">{error}</div>}
            <div className="row end">
              <button className="ghost" onClick={props.onClose}>
                Close
              </button>
              <button
                className="ghost danger"
                disabled={busy}
                onClick={() => run(async () => {
                  await disableTwoFactor(props.session, code);
                  setEnabled(false);
                  setCode("");
                })}
              >
                Disable 2FA
              </button>
            </div>
          </>
        ) : setup ? (
          <>
            <p className="muted">
              Add this secret to your authenticator app (or paste the otpauth URI), then enter a code to confirm.
            </p>
            <label>Secret</label>
            <input readOnly value={setup.secret} onFocus={(e) => e.currentTarget.select()} />
            <label>otpauth URI</label>
            <input readOnly value={setup.otpauthUri} onFocus={(e) => e.currentTarget.select()} />
            <label>Code from your app</label>
            <input value={code} onChange={(e) => setCode(e.target.value)} placeholder="6-digit code" inputMode="numeric" autoFocus />
            {error && <div className="error">{error}</div>}
            <div className="row end">
              <button className="ghost" onClick={props.onClose}>
                Cancel
              </button>
              <button
                className="primary"
                disabled={busy}
                onClick={() => run(async () => {
                  await enableTwoFactor(props.session, code);
                  setEnabled(true);
                  setSetup(null);
                  setCode("");
                })}
              >
                Enable
              </button>
            </div>
          </>
        ) : (
          <>
            <p className="muted">Protect your account with a time-based one-time code (TOTP).</p>
            {error && <div className="error">{error}</div>}
            <div className="row end">
              <button className="ghost" onClick={props.onClose}>
                Close
              </button>
              <button
                className="primary"
                disabled={busy}
                onClick={() => run(async () => setSetup(await setupTwoFactor(props.session)))}
              >
                Set up 2FA
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function ItemEditor(props: { item: VaultItem; onCancel: () => void; onSave: (i: VaultItem) => void }) {
  const [item, setItem] = useState<VaultItem>(props.item);
  const set = (k: keyof VaultItem, v: string) => setItem((prev) => ({ ...prev, [k]: v }));

  return (
    <div className="modal-backdrop" onClick={props.onCancel}>
      <div className="card modal" onClick={(e) => e.stopPropagation()}>
        <h2>{item.id ? "Edit item" : "Add item"}</h2>
        <label>Name</label>
        <input value={item.name} onChange={(e) => set("name", e.target.value)} placeholder="GitHub" autoFocus />
        <label>URL</label>
        <input value={item.url} onChange={(e) => set("url", e.target.value)} placeholder="https://github.com" />
        <label>Username</label>
        <input value={item.username} onChange={(e) => set("username", e.target.value)} placeholder="you@example.com" />
        <label>Password</label>
        <div className="row">
          <input value={item.password} onChange={(e) => set("password", e.target.value)} />
          <button type="button" className="ghost" onClick={() => set("password", generatePassword())}>
            Generate
          </button>
        </div>
        <label>Notes</label>
        <textarea value={item.notes} onChange={(e) => set("notes", e.target.value)} rows={3} />
        <div className="row end">
          <button className="ghost" onClick={props.onCancel}>
            Cancel
          </button>
          <button className="primary" onClick={() => props.onSave(item)}>
            Save
          </button>
        </div>
      </div>
    </div>
  );
}
