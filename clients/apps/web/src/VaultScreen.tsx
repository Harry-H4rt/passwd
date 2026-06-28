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
import { Icon } from "./components/Icon";
import { PasswordField } from "./components/PasswordField";
import { AsyncButton } from "./components/AsyncButton";

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
  const [toast, setToast] = useState<string | null>(null);

  function flash(msg: string) {
    setToast(msg);
    setTimeout(() => setToast(null), 1300);
  }

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

  // Returns true on success so the editor's button can show its "Saved" state
  // before the modal closes.
  async function handleSave(item: VaultItem): Promise<boolean> {
    try {
      if (item.id) await saveItem(session, item);
      else await addItem(session, stripId(item));
      await reload();
      flash("Saved");
      return true;
    } catch (e) {
      setError(e instanceof Error ? e.message : "Save failed.");
      return false;
    }
  }

  async function handleDelete(item: VaultItem) {
    if (!confirm(`Delete "${item.name || "this item"}"?`)) return;
    try {
      await removeItem(session, item.id);
      await reload();
      flash("Deleted");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Delete failed.");
    }
  }

  async function copy(label: string, value: string) {
    await navigator.clipboard.writeText(value);
    flash(`Copied ${label}`);
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
        <span className="brand">
          <Icon name="lock" size={18} /> passwd
        </span>
        <span className="account" title={session.identifier}>
          {session.identifier}
        </span>
        <button className="ghost" onClick={() => setShow2fa(true)}>
          2FA
        </button>
        <button className="ghost" onClick={props.onLock}>
          Lock
        </button>
      </header>

      {props.recovery && (
        <div className="recovery">
          <strong>Save your recovery passphrase.</strong> This is the only way back into your
          account, and there is no reset. Store it somewhere safe (not in this vault).
          <pre>{props.recovery}</pre>
          <div className="row">
            <button className="ghost" onClick={() => copy("recovery passphrase", props.recovery!)}>
              Copy
            </button>
            <button className="ghost" onClick={props.onDismissRecovery}>
              I've saved it
            </button>
          </div>
        </div>
      )}

      <div className="toolbar">
        <input className="search" placeholder="Search" value={query} onChange={(e) => setQuery(e.target.value)} />
        <button className="primary" onClick={() => setEditing({ id: "", ...blankFields() })}>
          Add item
        </button>
      </div>

      {error && <div className="error banner">{error}</div>}

      {loading ? (
        <p className="muted center-text">Decrypting vault...</p>
      ) : filtered.length === 0 ? (
        <p className="muted center-text">No items yet. Click "Add item" to store your first password.</p>
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
                  <button className="ghost" onClick={() => copy("password", item.password)}>
                    Copy
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
      {toast && <div className="toast">{toast}</div>}
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

function ItemEditor(props: {
  item: VaultItem;
  onCancel: () => void;
  onSave: (i: VaultItem) => Promise<boolean>;
}) {
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
          <div style={{ flex: 1 }}>
            <PasswordField value={item.password} onChange={(v) => set("password", v)} />
          </div>
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
          <AsyncButton
            variant="primary"
            loadingLabel="Saving"
            successLabel="Saved"
            onClick={() => props.onSave(item)}
            onSuccess={props.onCancel}
          >
            Save
          </AsyncButton>
        </div>
      </div>
    </div>
  );
}

function TwoFactor(props: { session: Session; onClose: () => void }) {
  const [loading, setLoading] = useState(true);
  const [enabled, setEnabled] = useState(false);
  const [setup, setSetup] = useState<{ secret: string; otpauthUri: string } | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getTwoFactorStatus(props.session)
      .then((s) => setEnabled(s.enabled))
      .catch((e) => setError(errMsg(e)))
      .finally(() => setLoading(false));
  }, [props.session]);

  return (
    <div className="modal-backdrop" onClick={props.onClose}>
      <div className="card modal" onClick={(e) => e.stopPropagation()}>
        <h2>Two-factor authentication</h2>
        {loading ? (
          <p className="muted">Loading...</p>
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
              <AsyncButton
                variant="ghost"
                danger
                loadingLabel="Disabling"
                successLabel="Disabled"
                onClick={async () => {
                  setError(null);
                  try {
                    await disableTwoFactor(props.session, code);
                    setEnabled(false);
                    setCode("");
                    return true;
                  } catch (e) {
                    setError(errMsg(e));
                    return false;
                  }
                }}
              >
                Disable 2FA
              </AsyncButton>
            </div>
          </>
        ) : setup ? (
          <>
            <p className="muted">
              Add this secret to your authenticator app (or paste the otpauth URI), then enter a
              code to confirm.
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
              <AsyncButton
                variant="primary"
                loadingLabel="Enabling"
                successLabel="Enabled"
                onClick={async () => {
                  setError(null);
                  try {
                    await enableTwoFactor(props.session, code);
                    setEnabled(true);
                    setSetup(null);
                    setCode("");
                    return true;
                  } catch (e) {
                    setError(errMsg(e));
                    return false;
                  }
                }}
              >
                Enable
              </AsyncButton>
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
              <AsyncButton
                variant="primary"
                loadingLabel="Starting"
                onClick={async () => {
                  setError(null);
                  try {
                    setSetup(await setupTwoFactor(props.session));
                    return true;
                  } catch (e) {
                    setError(errMsg(e));
                    return false;
                  }
                }}
              >
                Set up 2FA
              </AsyncButton>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
