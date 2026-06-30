import { useEffect, useState, type ReactNode } from "react";
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
  listPasskeys,
  enrollPasskey,
  removePasskey,
  getRecoveryStatus,
  enableRecovery,
  disableRecovery,
  getActivity,
  type ActivityEvent,
  type WebAuthnCredentialSummary,
} from "@passwd/api-client";
import { Icon } from "./components/Icon";
import { PasswordField } from "./components/PasswordField";
import { AsyncButton } from "./components/AsyncButton";
import { ThemeToggle } from "./components/ThemeToggle";
import { ImportExport } from "./ImportExport";

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
  const [showPasskeys, setShowPasskeys] = useState(false);
  const [showRecovery, setShowRecovery] = useState(false);
  const [showActivity, setShowActivity] = useState(false);
  const [showData, setShowData] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [accountOpen, setAccountOpen] = useState(false);

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

  // Persist just the notes (inline edit from the detail pane).
  async function saveNotes(item: VaultItem, notes: string) {
    if (notes === item.notes) return;
    try {
      await saveItem(session, { ...item, notes });
      await reload();
      flash("Notes saved");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Save failed.");
    }
  }

  async function handleDelete(item: VaultItem) {
    if (!confirm(`Delete "${item.name || "this item"}"?`)) return;
    try {
      await removeItem(session, item.id);
      if (selectedId === item.id) setSelectedId(null);
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

  const selected = items.find((i) => i.id === selectedId) ?? null;

  return (
    <div className="vault-layout">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <Icon name="lock" size={20} /> <span>passwd</span>
        </div>
        <button className="primary add-btn" onClick={() => setEditing({ id: "", ...blankFields() })}>
          + Add item
        </button>
        <nav className="sidebar-nav">
          <button className="nav-item" onClick={() => setShowData(true)}>
            <Icon name="copy" size={16} /> Import / export
          </button>
          <button className="nav-item" onClick={() => setShow2fa(true)}>
            <Icon name="settings" size={16} /> Two-factor (2FA)
          </button>
          <button className="nav-item" onClick={() => setShowPasskeys(true)}>
            <Icon name="lock" size={16} /> Passkeys
          </button>
          <button className="nav-item" onClick={() => setShowRecovery(true)}>
            <Icon name="key" size={16} /> Recovery code
          </button>
          <button className="nav-item" onClick={() => setShowActivity(true)}>
            <Icon name="clock" size={16} /> Activity
          </button>
        </nav>
        <div className="sidebar-footer">
          <button
            className="account-btn"
            onClick={() => {
              setAccountOpen(true);
              setSelectedId(null);
            }}
            title={session.identifier}
          >
            <Icon name="user" size={16} />
            <span className="account-id">{session.identifier}</span>
          </button>
          <div className="sidebar-footer-row">
            <button className="ghost" onClick={props.onLock}>
              Lock
            </button>
            <ThemeToggle />
          </div>
        </div>
      </aside>

      <section className="list-col">
        <div className="search-field">
          <Icon name="search" size={16} />
          <input className="search" placeholder="Search" value={query} onChange={(e) => setQuery(e.target.value)} />
        </div>
        {error && <div className="error banner">{error}</div>}
        {loading ? (
          <p className="muted center-text">Decrypting vault...</p>
        ) : filtered.length === 0 ? (
          <p className="muted center-text">No items yet. Use "+ Add item" to store your first password.</p>
        ) : (
          <ul className="items">
            {filtered.map((item) => (
              <li
                key={item.id}
                className={"item" + (item.id === selectedId && !accountOpen ? " selected" : "")}
                onClick={() => {
                  setAccountOpen(false);
                  setSelectedId(item.id);
                }}
              >
                <div className="item-main">
                  <div className="item-name">{item.name || "(unnamed)"}</div>
                  <div className="item-sub">{item.username || item.url || "no details"}</div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="detail-col">
        {props.recovery && (
          <div className="recovery">
            <strong>Save your recovery passphrase.</strong> This is the only way back into your account, and there is no
            reset. Store it somewhere safe (not in this vault).
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
        {accountOpen ? (
          <AccountPanel identifier={session.identifier} onCopy={copy} />
        ) : selected ? (
          <ItemDetail
            key={selected.id}
            item={selected}
            onCopy={copy}
            onEdit={() => setEditing(selected)}
            onDelete={() => handleDelete(selected)}
            onSaveNotes={(notes) => saveNotes(selected, notes)}
          />
        ) : (
          !props.recovery && (
            <div className="detail-empty">
              <Icon name="lock" size={30} />
              <p className="muted">Select an item to view its details.</p>
            </div>
          )
        )}
      </section>

      {editing && <ItemEditor item={editing} onCancel={() => setEditing(null)} onSave={handleSave} />}
      {show2fa && <TwoFactor session={session} onClose={() => setShow2fa(false)} />}
      {showPasskeys && <Passkeys session={session} onClose={() => setShowPasskeys(false)} />}
      {showRecovery && <RecoveryCode session={session} onClose={() => setShowRecovery(false)} />}
      {showActivity && <Activity session={session} onClose={() => setShowActivity(false)} />}
      {showData && (
        <ImportExport
          session={session}
          items={items}
          onClose={() => setShowData(false)}
          onImported={() => {
            void reload();
            flash("Imported");
          }}
        />
      )}
      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}

function Passkeys(props: { session: Session; onClose: () => void }) {
  const [loading, setLoading] = useState(true);
  const [creds, setCreds] = useState<WebAuthnCredentialSummary[]>([]);
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);

  function refresh() {
    return listPasskeys(props.session)
      .then(setCreds)
      .catch((e) => setError(errMsg(e)));
  }

  useEffect(() => {
    refresh().finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [props.session]);

  const supported = typeof window !== "undefined" && !!window.PublicKeyCredential;

  return (
    <div className="modal-backdrop" onClick={props.onClose}>
      <div className="card modal" onClick={(e) => e.stopPropagation()}>
        <h2>Passkeys</h2>
        <p className="muted">
          A passkey is a phishing-resistant second factor: at sign-in you confirm with your
          device (Touch ID, Windows Hello, or a security key) instead of, or alongside, a code.
        </p>
        {!supported && (
          <div className="error">This browser does not support passkeys.</div>
        )}
        {loading ? (
          <p className="muted">Loading...</p>
        ) : (
          <>
            {creds.length > 0 ? (
              <ul className="passkey-list">
                {creds.map((c) => (
                  <li key={c.id} className="passkey-row">
                    <span>
                      <strong>{c.name}</strong>
                      <span className="muted"> · added {new Date(c.createdAt).toLocaleDateString()}</span>
                    </span>
                    <AsyncButton
                      variant="ghost"
                      danger
                      loadingLabel="Removing"
                      successLabel="Removed"
                      onClick={async () => {
                        setError(null);
                        try {
                          await removePasskey(props.session, c.id);
                          await refresh();
                          return true;
                        } catch (e) {
                          setError(errMsg(e));
                          return false;
                        }
                      }}
                    >
                      Remove
                    </AsyncButton>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="muted">No passkeys yet.</p>
            )}
            <label>Name a new passkey</label>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. MacBook Touch ID"
              autoFocus
            />
            {error && <div className="error">{error}</div>}
            <div className="row end">
              <button className="ghost" onClick={props.onClose}>
                Close
              </button>
              <AsyncButton
                variant="primary"
                loadingLabel="Waiting for device"
                successLabel="Added"
                onClick={async () => {
                  setError(null);
                  if (!supported) return false;
                  try {
                    await enrollPasskey(props.session, name.trim() || "Passkey");
                    setName("");
                    await refresh();
                    return true;
                  } catch (e) {
                    setError(errMsg(e));
                    return false;
                  }
                }}
              >
                Add passkey
              </AsyncButton>
            </div>
          </>
        )}
      </div>
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

function normalizeUrl(url: string): string {
  return /^https?:\/\//i.test(url) ? url : `https://${url}`;
}

// Read-only detail view for the selected item. Password is masked until revealed.
function ItemDetail(props: {
  item: VaultItem;
  onCopy: (label: string, value: string) => void;
  onEdit: () => void;
  onDelete: () => void;
  onSaveNotes: (notes: string) => void;
}) {
  const { item } = props;
  const [reveal, setReveal] = useState(false);
  const [notes, setNotes] = useState(item.notes);

  return (
    <div className="detail">
      <div className="detail-head">
        <h2>{item.name || "(unnamed)"}</h2>
        <div className="detail-actions">
          <button className="ghost" onClick={props.onEdit}>
            <Icon name="edit" size={16} /> Edit
          </button>
          <button className="ghost danger" onClick={props.onDelete}>
            <Icon name="trash" size={16} /> Delete
          </button>
        </div>
      </div>

      <div className="detail-body">
        <div className="detail-fields">
          {item.url && (
            <DetailField label="Website" onCopy={() => props.onCopy("website", item.url)}>
              <a className="val" href={normalizeUrl(item.url)} target="_blank" rel="noreferrer">
                {item.url}
              </a>
            </DetailField>
          )}
          {item.username && (
            <DetailField label="Username" onCopy={() => props.onCopy("username", item.username)}>
              <span className="val">{item.username}</span>
            </DetailField>
          )}
          {item.password && (
            <DetailField
              label="Password"
              onCopy={() => props.onCopy("password", item.password)}
              extra={
                <button
                  className="icon-btn"
                  onClick={() => setReveal((r) => !r)}
                  aria-label={reveal ? "Hide password" : "Reveal password"}
                  title={reveal ? "Hide password" : "Reveal password"}
                >
                  <Icon name={reveal ? "eyeOff" : "eye"} size={16} />
                </button>
              }
            >
              <span className="val pw-val">
                {reveal ? item.password : "•".repeat(Math.min(item.password.length, 16))}
              </span>
            </DetailField>
          )}
          {!item.url && !item.username && !item.password && (
            <p className="muted">No login fields. Use Edit to add some.</p>
          )}
        </div>

        <div className="detail-notes">
          <label>Notes</label>
          <textarea
            className="notes-edit"
            value={notes}
            placeholder="Click to add notes..."
            onChange={(e) => setNotes(e.target.value)}
            onBlur={() => props.onSaveNotes(notes)}
          />
        </div>
      </div>
    </div>
  );
}

// Account view: shows the full login identifier (which is truncated in the
// sidebar) with a copy button.
function AccountPanel(props: { identifier: string; onCopy: (label: string, value: string) => void }) {
  return (
    <div className="detail">
      <div className="detail-head">
        <h2>Account</h2>
      </div>
      <div className="detail-fields">
        <DetailField label="Account identifier" onCopy={() => props.onCopy("identifier", props.identifier)}>
          <span className="val val-wrap">{props.identifier}</span>
        </DetailField>
        <p className="muted">
          This is your login handle (a private passphrase or email). It is blinded before it reaches the server, which
          never sees it in the clear.
        </p>
      </div>
    </div>
  );
}

function DetailField(props: { label: string; onCopy: () => void; extra?: ReactNode; children: ReactNode }) {
  return (
    <div className="detail-field">
      <label>{props.label}</label>
      <div className="detail-value">
        {props.children}
        {props.extra}
        <button className="icon-btn" onClick={props.onCopy} aria-label={`Copy ${props.label}`} title={`Copy ${props.label}`}>
          <Icon name="copy" size={16} />
        </button>
      </div>
    </div>
  );
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

const ACTIVITY_LABELS: Record<string, string> = {
  "account.register": "Account created",
  "login.success": "Signed in",
  "login.failure": "Failed sign-in attempt",
  "totp.enable": "Two-factor (TOTP) enabled",
  "totp.disable": "Two-factor (TOTP) disabled",
  "passkey.enroll": "Passkey added",
  "passkey.remove": "Passkey removed",
  "recovery.enable": "Recovery code set up",
  "recovery.disable": "Recovery code removed",
  "recovery.complete": "Account recovered",
  "token.reuse_detected": "Session token reuse detected",
  "cipher.create": "Item added",
  "cipher.update": "Item edited",
  "cipher.delete": "Item deleted",
};

function Activity(props: { session: Session; onClose: () => void }) {
  const [events, setEvents] = useState<ActivityEvent[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getActivity(props.session)
      .then(setEvents)
      .catch((e) => setError(errMsg(e)));
  }, [props.session]);

  return (
    <div className="modal-backdrop" onClick={props.onClose}>
      <div className="card modal" onClick={(e) => e.stopPropagation()}>
        <h2>Account activity</h2>
        <p className="muted">Recent security events on your account, newest first.</p>
        {error && <div className="error">{error}</div>}
        {!events ? (
          <p className="muted">Loading...</p>
        ) : events.length === 0 ? (
          <p className="muted">No activity yet.</p>
        ) : (
          <ul className="activity-list">
            {events.map((e, i) => (
              <li key={i} className="activity-row">
                <span className={"activity-label" + (e.event.endsWith(".failure") || e.event === "token.reuse_detected" ? " danger" : "")}>
                  {ACTIVITY_LABELS[e.event] ?? e.event}
                </span>
                <span className="activity-time">{new Date(e.createdAt).toLocaleString()}</span>
              </li>
            ))}
          </ul>
        )}
        <div className="row end">
          <button className="ghost" onClick={props.onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

function RecoveryCode(props: { session: Session; onClose: () => void }) {
  const [loading, setLoading] = useState(true);
  const [enabled, setEnabled] = useState(false);
  // The 24-word code, held only in memory and shown once right after enrolling.
  const [code, setCode] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getRecoveryStatus(props.session)
      .then((s) => setEnabled(s.enabled))
      .catch((e) => setError(errMsg(e)))
      .finally(() => setLoading(false));
  }, [props.session]);

  async function generate() {
    setError(null);
    try {
      setCode(await enableRecovery(props.session));
      setEnabled(true);
      return true;
    } catch (e) {
      setError(errMsg(e));
      return false;
    }
  }

  return (
    <div className="modal-backdrop" onClick={props.onClose}>
      <div className="card modal" onClick={(e) => e.stopPropagation()}>
        <h2>Recovery code</h2>
        {loading ? (
          <p className="muted">Loading...</p>
        ) : code ? (
          <>
            <p className="muted">
              Write down these 24 words and keep them somewhere safe and offline. They are the only
              way back into your vault if you forget your master password, and they will not be shown
              again. Anyone with this code can reset your password, so guard it like the password
              itself.
            </p>
            <pre className="recovery-code">{code}</pre>
            {error && <div className="error">{error}</div>}
            <div className="row end">
              <AsyncButton
                variant="ghost"
                successLabel="Copied"
                onClick={async () => {
                  await navigator.clipboard.writeText(code);
                  return true;
                }}
              >
                Copy
              </AsyncButton>
              <button className="primary" onClick={props.onClose}>
                I've saved it
              </button>
            </div>
          </>
        ) : enabled ? (
          <>
            <p className="muted">
              A recovery code is <strong>set up</strong>. You can generate a new one (which replaces
              the old) or remove it. Removing it means a forgotten master password cannot be
              recovered.
            </p>
            {error && <div className="error">{error}</div>}
            <div className="row end">
              <AsyncButton
                variant="ghost"
                danger
                loadingLabel="Removing"
                successLabel="Removed"
                onClick={async () => {
                  setError(null);
                  try {
                    await disableRecovery(props.session);
                    setEnabled(false);
                    return true;
                  } catch (e) {
                    setError(errMsg(e));
                    return false;
                  }
                }}
              >
                Remove
              </AsyncButton>
              <AsyncButton variant="primary" loadingLabel="Generating" onClick={generate}>
                Generate new code
              </AsyncButton>
            </div>
          </>
        ) : (
          <>
            <p className="muted">
              Set up a recovery code so you can get back into your vault if you ever forget your
              master password. It is generated on this device and shown only once; we never see it.
            </p>
            {error && <div className="error">{error}</div>}
            <div className="row end">
              <button className="ghost" onClick={props.onClose}>
                Close
              </button>
              <AsyncButton variant="primary" loadingLabel="Generating" onClick={generate}>
                Set up recovery code
              </AsyncButton>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
