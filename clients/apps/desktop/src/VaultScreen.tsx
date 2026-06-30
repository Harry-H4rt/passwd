import { useMemo, useState } from "react";
import { masterPasswordIssue } from "@passwd/crypto";
import { Icon } from "./components/Icon";
import { PasswordField } from "./components/PasswordField";
import { AsyncButton } from "./components/AsyncButton";
import { ThemeToggle } from "./components/ThemeToggle";
import { type DesktopVault, persist, rekey, basename } from "./storage";
import { type VaultItem, blankItem, newItemId, generatePassword } from "./types";
import { errMsg } from "./App";

// Clear a copied secret from the OS clipboard after this long.
const CLIPBOARD_CLEAR_MS = 20_000;

export function VaultScreen(props: {
  vault: DesktopVault;
  onChange: (v: DesktopVault) => void;
  onLock: () => void;
}) {
  const { vault } = props;
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [editing, setEditing] = useState<VaultItem | null>(null);
  const [showChangePw, setShowChangePw] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  function flash(msg: string) {
    setToast(msg);
    setTimeout(() => setToast(null), 1200);
  }

  async function copy(label: string, value: string) {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      flash(`Copied ${label}`);
      // Don't let a copied secret linger on the clipboard.
      window.setTimeout(() => void navigator.clipboard.writeText("").catch(() => {}), CLIPBOARD_CLEAR_MS);
    } catch {
      flash("Copy failed");
    }
  }

  async function commit(items: VaultItem[]): Promise<void> {
    const next = { ...vault, items };
    await persist(next);
    props.onChange(next);
  }

  async function saveItem(item: VaultItem): Promise<string | null> {
    const withId = item.id ? item : { ...item, id: newItemId() };
    const exists = vault.items.some((i) => i.id === withId.id);
    const items = exists
      ? vault.items.map((i) => (i.id === withId.id ? withId : i))
      : [...vault.items, withId];
    try {
      await commit(items);
      setEditing(null);
      setSelectedId(withId.id);
      flash(item.id ? "Saved" : "Added");
      return null;
    } catch (e) {
      return errMsg(e);
    }
  }

  async function deleteItem(item: VaultItem) {
    if (!confirm(`Delete "${item.name || "this item"}"?`)) return;
    setError(null);
    try {
      await commit(vault.items.filter((i) => i.id !== item.id));
      if (selectedId === item.id) setSelectedId(null);
      flash("Deleted");
    } catch (e) {
      setError(errMsg(e));
    }
  }

  const filtered = useMemo(() => {
    const q = query.toLowerCase();
    return vault.items
      .filter(
        (i) =>
          !q ||
          i.name.toLowerCase().includes(q) ||
          i.username.toLowerCase().includes(q) ||
          i.url.toLowerCase().includes(q),
      )
      .sort((a, b) => (a.name || a.url).localeCompare(b.name || b.url));
  }, [vault.items, query]);

  const selected = vault.items.find((i) => i.id === selectedId) ?? null;

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <Icon name="lock" size={18} /> <span>passwd</span>
        </div>
        <span className="vault-name ellipsis" title={vault.path}>
          {basename(vault.path)}
        </span>
        <div className="topbar-actions">
          <button className="ghost" onClick={() => setEditing(blankItem())}>
            + Add
          </button>
          <button className="ghost" onClick={() => setShowChangePw(true)}>
            <Icon name="settings" size={16} /> Password
          </button>
          <ThemeToggle />
          <button className="ghost" onClick={props.onLock}>
            <Icon name="lock" size={16} /> Lock
          </button>
        </div>
      </header>

      {error && <div className="error toperror">{error}</div>}

      <div className="panes">
        <section className="list-pane">
          <div className="search-row">
            <Icon name="search" size={16} />
            <input placeholder="Search" value={query} onChange={(e) => setQuery(e.target.value)} />
          </div>
          {filtered.length === 0 ? (
            <p className="muted empty">No items{query ? " match" : " yet"}.</p>
          ) : (
            <ul className="items">
              {filtered.map((item) => (
                <li
                  key={item.id}
                  className={item.id === selectedId ? "active" : ""}
                  onClick={() => setSelectedId(item.id)}
                >
                  <div className="item-name">{item.name || "(unnamed)"}</div>
                  <div className="item-sub">{item.username || item.url}</div>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="detail-pane">
          {selected ? (
            <ItemDetail
              key={selected.id}
              item={selected}
              onCopy={copy}
              onEdit={() => setEditing(selected)}
              onDelete={() => deleteItem(selected)}
            />
          ) : (
            <div className="detail-empty">
              <Icon name="lock" size={30} />
              <p className="muted">Select an item to view its details.</p>
            </div>
          )}
        </section>
      </div>

      {editing && <ItemEditor item={editing} onCancel={() => setEditing(null)} onSave={saveItem} />}
      {showChangePw && (
        <ChangePassword
          vault={vault}
          onClose={() => setShowChangePw(false)}
          onChanged={(v) => {
            props.onChange(v);
            setShowChangePw(false);
            flash("Master password changed");
          }}
        />
      )}
      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}

function ItemDetail(props: {
  item: VaultItem;
  onCopy: (label: string, value: string) => void;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const { item } = props;
  const [shown, setShown] = useState(false);
  return (
    <div className="detail">
      <div className="detail-head">
        <h2 className="ellipsis">{item.name || "(unnamed)"}</h2>
        <div className="row">
          <button className="ghost" onClick={props.onEdit}>
            <Icon name="edit" size={16} /> Edit
          </button>
          <button className="ghost danger" onClick={props.onDelete}>
            <Icon name="trash" size={16} /> Delete
          </button>
        </div>
      </div>

      <DetailRow label="Username" value={item.username} onCopy={() => props.onCopy("username", item.username)} />
      <div className="field">
        <label>Password</label>
        <div className="field-row">
          <span className="field-value mono">
            {item.password ? (shown ? item.password : "••••••••••") : <span className="muted">—</span>}
          </span>
          {item.password && (
            <>
              <button className="reveal icon-only" onClick={() => setShown((s) => !s)} title={shown ? "Hide" : "Show"}>
                <Icon name={shown ? "eyeOff" : "eye"} size={16} />
              </button>
              <button className="reveal icon-only" onClick={() => props.onCopy("password", item.password)} title="Copy">
                <Icon name="copy" size={16} />
              </button>
            </>
          )}
        </div>
      </div>
      <DetailRow label="URL" value={item.url} onCopy={() => props.onCopy("URL", item.url)} />
      {item.notes && (
        <div className="field">
          <label>Notes</label>
          <div className="notes">{item.notes}</div>
        </div>
      )}
    </div>
  );
}

function DetailRow(props: { label: string; value: string; onCopy: () => void }) {
  return (
    <div className="field">
      <label>{props.label}</label>
      <div className="field-row">
        <span className="field-value ellipsis">{props.value || <span className="muted">—</span>}</span>
        {props.value && (
          <button className="reveal icon-only" onClick={props.onCopy} title="Copy">
            <Icon name="copy" size={16} />
          </button>
        )}
      </div>
    </div>
  );
}

function ItemEditor(props: {
  item: VaultItem;
  onCancel: () => void;
  onSave: (i: VaultItem) => Promise<string | null>;
}) {
  const [item, setItem] = useState<VaultItem>(props.item);
  const [error, setError] = useState<string | null>(null);
  const set = (k: keyof VaultItem, v: string) => setItem((p) => ({ ...p, [k]: v }));
  const isNew = !item.id;

  return (
    <div className="modal-backdrop" onClick={props.onCancel}>
      <div className="card modal" onClick={(e) => e.stopPropagation()}>
        <h2>{isNew ? "Add item" : "Edit item"}</h2>
        <label>Name</label>
        <input value={item.name} onChange={(e) => set("name", e.target.value)} placeholder="GitHub" autoFocus />
        <label>URL</label>
        <input value={item.url} onChange={(e) => set("url", e.target.value)} placeholder="https://github.com" />
        <label>Username</label>
        <input value={item.username} onChange={(e) => set("username", e.target.value)} placeholder="you@example.com" />
        <label>Password</label>
        <div className="pwfield">
          <input value={item.password} onChange={(e) => set("password", e.target.value)} placeholder="password" />
          <button
            type="button"
            className="reveal icon-only"
            onClick={() => set("password", generatePassword())}
            title="Generate a strong password"
          >
            <Icon name="dice" size={18} />
          </button>
        </div>
        <label>Notes</label>
        <textarea value={item.notes} onChange={(e) => set("notes", e.target.value)} rows={3} />
        {error && <div className="error">{error}</div>}
        <div className="row end">
          <button className="ghost" onClick={props.onCancel}>
            Cancel
          </button>
          <AsyncButton
            variant="primary"
            loadingLabel="Saving"
            successLabel="Saved"
            onClick={async () => {
              setError(null);
              if (!item.name.trim() && !item.username.trim() && !item.url.trim()) {
                setError("Give the item a name, username, or URL.");
                return false;
              }
              const err = await props.onSave(item);
              if (err) {
                setError(err);
                return false;
              }
              return true;
            }}
          >
            Save
          </AsyncButton>
        </div>
      </div>
    </div>
  );
}

function ChangePassword(props: {
  vault: DesktopVault;
  onClose: () => void;
  onChanged: (v: DesktopVault) => void;
}) {
  const [pw, setPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);

  return (
    <div className="modal-backdrop" onClick={props.onClose}>
      <div className="card modal" onClick={(e) => e.stopPropagation()}>
        <h2>Change master password</h2>
        <p className="muted">Re-keys this vault file. Items are not re-encrypted, only the wrapping key.</p>
        <label>New master password</label>
        <PasswordField value={pw} onChange={setPw} placeholder="at least 12 characters" autoFocus />
        <label>Confirm</label>
        <PasswordField value={confirm} onChange={setConfirm} placeholder="type it again" />
        {error && <div className="error">{error}</div>}
        <div className="row end">
          <button className="ghost" onClick={props.onClose}>
            Cancel
          </button>
          <AsyncButton
            variant="primary"
            loadingLabel="Re-keying"
            successLabel="Changed"
            onClick={async () => {
              setError(null);
              const weak = masterPasswordIssue(pw);
              if (weak) {
                setError(weak);
                return false;
              }
              if (pw !== confirm) {
                setError("The passwords don't match.");
                return false;
              }
              try {
                props.onChanged(await rekey(props.vault, pw));
                return true;
              } catch (e) {
                setError(errMsg(e));
                return false;
              }
            }}
          >
            Change password
          </AsyncButton>
        </div>
      </div>
    </div>
  );
}
