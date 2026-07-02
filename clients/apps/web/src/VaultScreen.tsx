import { useEffect, useMemo, useState, type ReactNode } from "react";
import {
  type Session,
  type VaultItem,
  type ItemType,
  type CustomField,
  ITEM_TYPES,
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
  getSessions,
  signOutEverywhere,
  type SessionInfo,
  deleteAccount,
  shareItem,
  listSharedWithMe,
  removeSharedItem,
  type ActivityEvent,
  type SharedItem,
  type WebAuthnCredentialSummary,
} from "@passwd/api-client";
import { normalizeIdentifier, totpFromString } from "@passwd/crypto";
import { passwordWeakness, reusedItemIds, breachedItemIds } from "./health";
import { biometricEnrolled, disableBiometric } from "./biometric";
import { Icon } from "./components/Icon";
import { PasswordField } from "./components/PasswordField";
import { AsyncButton } from "./components/AsyncButton";
import { ThemeToggle } from "./components/ThemeToggle";
import { ImportExport } from "./ImportExport";

// Local marker of the newest security event this account has already been shown,
// keyed by a SHA-256 of the normalized identifier so the plaintext handle (which
// may be a secret passphrase) never lands in localStorage.
async function lastSeenKey(identifier: string): Promise<string> {
  const data = new TextEncoder().encode(normalizeIdentifier(identifier));
  const digest = await crypto.subtle.digest("SHA-256", data);
  return (
    "passwd:lastSeenActivity:" +
    Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
  );
}

function buildLoginAlert(failures: number, reuse: boolean): string {
  const parts: string[] = [];
  if (failures > 0) parts.push(`${failures} failed sign-in attempt${failures === 1 ? "" : "s"}`);
  if (reuse) parts.push("session token reuse");
  return `Since your last visit: ${parts.join(" and ")}. If that wasn't you, review your activity.`;
}

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
  const [showSecurity, setShowSecurity] = useState(false);
  const [showShared, setShowShared] = useState(false);
  const [sharing, setSharing] = useState<VaultItem | null>(null);
  const [showData, setShowData] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [accountOpen, setAccountOpen] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false); // mobile sidebar drawer
  const [loginAlert, setLoginAlert] = useState<string | null>(null);

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

  // Proactive login awareness. On unlock, compare the server-side security log
  // against the newest event this device has already seen, and surface a banner
  // for any failed sign-ins or session-token reuse since then. Pull-based and
  // zero-knowledge: nothing is emailed and the server learns nothing new.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const events = await getActivity(session);
        if (cancelled) return;
        const key = await lastSeenKey(session.identifier);
        const lastSeenRaw = localStorage.getItem(key);
        // First run on this device: set a baseline, don't alarm about history.
        if (lastSeenRaw !== null) {
          const lastSeen = Number(lastSeenRaw);
          const since = events.filter(
            (e) =>
              new Date(e.createdAt).getTime() > lastSeen &&
              (e.event === "login.failure" || e.event === "token.reuse_detected"),
          );
          const failures = since.filter((e) => e.event === "login.failure").length;
          const reuse = since.some((e) => e.event === "token.reuse_detected");
          if (!cancelled && (failures > 0 || reuse)) setLoginAlert(buildLoginAlert(failures, reuse));
        }
        // Mark up to the newest event's server timestamp (same clock we compare
        // against next time), falling back to now when the log is empty.
        const newest = events.length ? new Date(events[0].createdAt).getTime() : Date.now();
        localStorage.setItem(key, String(newest));
      } catch {
        // Non-critical: the Activity panel is still available on demand.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [session]);

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

  const filtered = items.filter((i) => !query || searchHaystack(i).includes(query.toLowerCase()));

  const selected = items.find((i) => i.id === selectedId) ?? null;
  // On mobile the layout is one pane at a time: the item list, or a full-screen
  // detail (an item, the account panel, or the post-signup recovery banner).
  const detailOpen = accountOpen || selected != null || props.recovery != null;

  function closeDetail() {
    setSelectedId(null);
    setAccountOpen(false);
  }

  return (
    <div className={"vault-layout" + (detailOpen ? " detail-open" : "") + (menuOpen ? " menu-open" : "")}>
      <header className="mobile-topbar">
        <button className="icon-btn" aria-label="Menu" onClick={() => setMenuOpen(true)}>
          <Icon name="menu" size={22} />
        </button>
        <span className="mobile-title">
          <Icon name="lock" size={18} /> passwd
        </span>
        <button className="icon-btn" aria-label="Add item" onClick={() => setEditing({ id: "", ...blankFields() })}>
          <Icon name="edit" size={20} />
        </button>
      </header>
      <div className="drawer-backdrop" onClick={() => setMenuOpen(false)} />

      <aside className="sidebar" onClick={() => setMenuOpen(false)}>
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
          <button className="nav-item" onClick={() => setShowSecurity(true)}>
            <Icon name="check" size={16} /> Security check
          </button>
          <button className="nav-item" onClick={() => setShowShared(true)}>
            <Icon name="share" size={16} /> Shared with me
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
        {loginAlert && (
          <div className="warn-banner">
            <div className="warn-banner-text">
              <Icon name="clock" size={16} />
              <span>{loginAlert}</span>
            </div>
            <div className="warn-banner-actions">
              <button
                className="linklike"
                onClick={() => {
                  setShowActivity(true);
                  setLoginAlert(null);
                }}
              >
                Review
              </button>
              <button className="linklike" onClick={() => setLoginAlert(null)}>
                Dismiss
              </button>
            </div>
          </div>
        )}
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
                <span className="item-ico" title={TYPE_META[item.type].label}>
                  <Icon name={TYPE_META[item.type].icon} size={16} />
                </span>
                <div className="item-main">
                  <div className="item-name">{item.name || "(unnamed)"}</div>
                  <div className="item-sub">{itemSubtitle(item)}</div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="detail-col">
        {!props.recovery && (
          <button className="mobile-back" onClick={closeDetail}>
            <Icon name="arrowLeft" size={16} /> Back
          </button>
        )}
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
          <AccountPanel identifier={session.identifier} session={session} onCopy={copy} onDeleted={props.onLock} />
        ) : selected ? (
          <ItemDetail
            key={selected.id}
            item={selected}
            onCopy={copy}
            onEdit={() => setEditing(selected)}
            onDelete={() => handleDelete(selected)}
            onShare={() => setSharing(selected)}
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
      {showSecurity && <SecurityCheck items={items} onClose={() => setShowSecurity(false)} />}
      {showShared && (
        <SharedWithMe session={session} onClose={() => setShowShared(false)} onCopy={copy} />
      )}
      {sharing && (
        <ShareDialog
          session={session}
          item={sharing}
          onClose={() => setSharing(null)}
          onShared={() => {
            setSharing(null);
            flash("Shared");
          }}
        />
      )}
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

// Per-type presentation: label, list icon, and the list row's subtitle.
const TYPE_META: Record<ItemType, { label: string; icon: string }> = {
  login: { label: "Login", icon: "key" },
  note: { label: "Note", icon: "note" },
  card: { label: "Card", icon: "card" },
  identity: { label: "Identity", icon: "user" },
};

function itemSubtitle(i: VaultItem): string {
  switch (i.type) {
    case "note":
      return i.notes.split("\n")[0]?.slice(0, 80) || "secure note";
    case "card": {
      const digits = i.card.number.replace(/\D/g, "");
      return digits ? "•••• " + digits.slice(-4) : "card";
    }
    case "identity":
      return i.identity.email || i.identity.fullName || "identity";
    default:
      return i.username || i.url || "no details";
  }
}

// Fields a search query should match, beyond the name.
function searchHaystack(i: VaultItem): string {
  return [i.name, i.username, i.url, i.identity.fullName, i.identity.email, i.card.cardholder]
    .join("\n")
    .toLowerCase();
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : "Something went wrong.";
}

function normalizeUrl(url: string): string {
  return /^https?:\/\//i.test(url) ? url : `https://${url}`;
}

// Live TOTP code for a login item's stored 2FA secret, regenerated every second
// on-device. Shows the remaining validity so users don't paste a dying code.
function TotpCode(props: { secret: string; onCopy: (label: string, value: string) => void }) {
  const [state, setState] = useState<{ code: string; secondsLeft: number } | "invalid" | null>(null);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      const r = await totpFromString(props.secret);
      if (alive) setState(r ?? "invalid");
    };
    void tick();
    const t = setInterval(tick, 1000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [props.secret]);

  if (state === "invalid") {
    return (
      <div className="detail-field">
        <label>2FA code</label>
        <p className="muted">The stored 2FA secret is not a valid TOTP secret.</p>
      </div>
    );
  }
  if (!state) return null;
  return (
    <DetailField
      label="2FA code"
      onCopy={() => props.onCopy("2FA code", state.code)}
      extra={<span className={"totp-timer" + (state.secondsLeft <= 5 ? " low" : "")}>{state.secondsLeft}s</span>}
    >
      <span className="val totp-val">{state.code.replace(/^(\d{3})(\d{3})$/, "$1 $2")}</span>
    </DetailField>
  );
}

// A value that renders masked until revealed (passwords, CVVs, hidden fields).
function SecretValue(props: { value: string }) {
  const [reveal, setReveal] = useState(false);
  return (
    <>
      <span className="val pw-val">{reveal ? props.value : "•".repeat(Math.min(props.value.length, 16))}</span>
      <button
        className="icon-btn"
        onClick={() => setReveal((r) => !r)}
        aria-label={reveal ? "Hide" : "Reveal"}
        title={reveal ? "Hide" : "Reveal"}
      >
        <Icon name={reveal ? "eyeOff" : "eye"} size={16} />
      </button>
    </>
  );
}

// Read-only detail view for the selected item; fields depend on its type.
// Secrets are masked until revealed.
function ItemDetail(props: {
  item: VaultItem;
  onCopy: (label: string, value: string) => void;
  onEdit: () => void;
  onDelete: () => void;
  onShare: () => void;
  onSaveNotes: (notes: string) => void;
}) {
  const { item } = props;
  const [notes, setNotes] = useState(item.notes);
  const copy = props.onCopy;

  const loginEmpty = !item.url && !item.username && !item.password && !item.totp;
  const cardExpiry = [item.card.expMonth, item.card.expYear].filter(Boolean).join(" / ");

  return (
    <div className="detail">
      <div className="detail-head">
        <h2>
          {item.name || "(unnamed)"}
          <span className="type-badge">{TYPE_META[item.type].label}</span>
        </h2>
        <div className="detail-actions">
          <button className="ghost" onClick={props.onEdit}>
            <Icon name="edit" size={16} /> Edit
          </button>
          <button className="ghost" onClick={props.onShare}>
            <Icon name="share" size={16} /> Share
          </button>
          <button className="ghost danger" onClick={props.onDelete}>
            <Icon name="trash" size={16} /> Delete
          </button>
        </div>
      </div>

      <div className="detail-body">
        <div className="detail-fields">
          {item.type === "login" && (
            <>
              {item.url && (
                <DetailField label="Website" onCopy={() => copy("website", item.url)}>
                  <a className="val" href={normalizeUrl(item.url)} target="_blank" rel="noreferrer">
                    {item.url}
                  </a>
                </DetailField>
              )}
              {item.username && (
                <DetailField label="Username" onCopy={() => copy("username", item.username)}>
                  <span className="val">{item.username}</span>
                </DetailField>
              )}
              {item.password && (
                <DetailField label="Password" onCopy={() => copy("password", item.password)}>
                  <SecretValue value={item.password} />
                </DetailField>
              )}
              {item.totp && <TotpCode secret={item.totp} onCopy={copy} />}
              {loginEmpty && <p className="muted">No login fields. Use Edit to add some.</p>}
            </>
          )}

          {item.type === "card" && (
            <>
              {item.card.cardholder && (
                <DetailField label="Cardholder" onCopy={() => copy("cardholder", item.card.cardholder)}>
                  <span className="val">{item.card.cardholder}</span>
                </DetailField>
              )}
              {item.card.number && (
                <DetailField label="Card number" onCopy={() => copy("card number", item.card.number)}>
                  <SecretValue value={item.card.number} />
                </DetailField>
              )}
              {cardExpiry && (
                <DetailField label="Expires" onCopy={() => copy("expiry", cardExpiry)}>
                  <span className="val">{cardExpiry}</span>
                </DetailField>
              )}
              {item.card.cvv && (
                <DetailField label="CVV" onCopy={() => copy("CVV", item.card.cvv)}>
                  <SecretValue value={item.card.cvv} />
                </DetailField>
              )}
              {!item.card.cardholder && !item.card.number && (
                <p className="muted">No card details yet. Use Edit to add them.</p>
              )}
            </>
          )}

          {item.type === "identity" && (
            <>
              {item.identity.fullName && (
                <DetailField label="Full name" onCopy={() => copy("full name", item.identity.fullName)}>
                  <span className="val">{item.identity.fullName}</span>
                </DetailField>
              )}
              {item.identity.email && (
                <DetailField label="Email" onCopy={() => copy("email", item.identity.email)}>
                  <span className="val">{item.identity.email}</span>
                </DetailField>
              )}
              {item.identity.phone && (
                <DetailField label="Phone" onCopy={() => copy("phone", item.identity.phone)}>
                  <span className="val">{item.identity.phone}</span>
                </DetailField>
              )}
              {item.identity.address && (
                <DetailField label="Address" onCopy={() => copy("address", item.identity.address)}>
                  <span className="val val-wrap">{item.identity.address}</span>
                </DetailField>
              )}
              {item.identity.company && (
                <DetailField label="Company" onCopy={() => copy("company", item.identity.company)}>
                  <span className="val">{item.identity.company}</span>
                </DetailField>
              )}
              {!item.identity.fullName && !item.identity.email && (
                <p className="muted">No identity details yet. Use Edit to add them.</p>
              )}
            </>
          )}

          {item.fields.map((f, i) => (
            <DetailField key={i} label={f.label || "Field"} onCopy={() => copy(f.label || "field", f.value)}>
              {f.hidden ? <SecretValue value={f.value} /> : <span className="val val-wrap">{f.value}</span>}
            </DetailField>
          ))}
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
function AccountPanel(props: {
  identifier: string;
  session: Session;
  onCopy: (label: string, value: string) => void;
  onDeleted: () => void;
}) {
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sessions, setSessions] = useState<SessionInfo[] | null>(null);
  const [signingOut, setSigningOut] = useState(false);
  const [bioOn, setBioOn] = useState(false);

  useEffect(() => {
    getSessions(props.session)
      .then(setSessions)
      .catch(() => setSessions([]));
    biometricEnrolled().then(setBioOn);
  }, [props.session]);

  async function signOutAll() {
    setError(null);
    setSigningOut(true);
    try {
      await signOutEverywhere(props.session);
      props.onDeleted(); // revokes every session; drop this one too
    } catch (e) {
      setError(errMsg(e));
      setSigningOut(false);
    }
  }

  async function del() {
    setError(null);
    setBusy(true);
    try {
      await deleteAccount(props.session);
      props.onDeleted();
    } catch (e) {
      setError(errMsg(e));
      setBusy(false);
    }
  }

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

        <div className="sessions-block">
          <h3>Active sessions</h3>
          <p className="muted">
            {sessions === null
              ? "Loading sessions..."
              : `${sessions.length} device${sessions.length === 1 ? "" : "s"} currently signed in.`}{" "}
            Signing out everywhere revokes every session; each device has to sign in again.
          </p>
          <button className="ghost" disabled={signingOut} onClick={signOutAll}>
            {signingOut ? "Signing out..." : "Sign out of all devices"}
          </button>
        </div>

        {bioOn && (
          <div className="sessions-block">
            <h3>Biometric unlock</h3>
            <p className="muted">
              This device can unlock your vault with a fingerprint or face. Your master password is held in the device's
              secure hardware store, released only after a biometric check.
            </p>
            <button className="ghost" onClick={() => disableBiometric().then(() => setBioOn(false))}>
              Disable biometric unlock
            </button>
          </div>
        )}

        <div className="danger-zone">
          <h3>Delete account</h3>
          <p className="muted">
            Permanently erases your account and every item, share, and security record. This cannot be undone: the
            server never held your master password, so there is nothing to recover afterward.
          </p>
          <label>
            Type <strong>DELETE</strong> to confirm
          </label>
          <input
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            placeholder="DELETE"
            autoComplete="off"
            spellCheck={false}
          />
          {error && <div className="error">{error}</div>}
          <button className="danger-btn" disabled={confirm !== "DELETE" || busy} onClick={del}>
            {busy ? "Deleting..." : "Delete my account"}
          </button>
        </div>
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
  const setCard = (k: keyof VaultItem["card"], v: string) =>
    setItem((prev) => ({ ...prev, card: { ...prev.card, [k]: v } }));
  const setIdentity = (k: keyof VaultItem["identity"], v: string) =>
    setItem((prev) => ({ ...prev, identity: { ...prev.identity, [k]: v } }));
  const setField = (i: number, patch: Partial<CustomField>) =>
    setItem((prev) => ({
      ...prev,
      fields: prev.fields.map((f, j) => (j === i ? { ...f, ...patch } : f)),
    }));

  const namePlaceholder = { login: "GitHub", note: "Wifi password", card: "Personal Visa", identity: "Me" }[
    item.type
  ];

  return (
    <div className="modal-backdrop" onClick={props.onCancel}>
      <div className="card modal" onClick={(e) => e.stopPropagation()}>
        <h2>{item.id ? "Edit item" : "Add item"}</h2>

        {/* The type is chosen at creation; changing it later would orphan the
            other type's fields, so existing items keep theirs. */}
        {!item.id && (
          <div className="type-tabs" role="tablist">
            {ITEM_TYPES.map((t) => (
              <button
                key={t}
                type="button"
                role="tab"
                aria-selected={item.type === t}
                className={"type-tab" + (item.type === t ? " active" : "")}
                onClick={() => setItem((prev) => ({ ...prev, type: t }))}
              >
                <Icon name={TYPE_META[t].icon} size={15} /> {TYPE_META[t].label}
              </button>
            ))}
          </div>
        )}

        <label>Name</label>
        <input value={item.name} onChange={(e) => set("name", e.target.value)} placeholder={namePlaceholder} autoFocus />

        {item.type === "login" && (
          <>
            <label>URL</label>
            <input value={item.url} onChange={(e) => set("url", e.target.value)} placeholder="https://github.com" />
            <label>Username</label>
            <input
              value={item.username}
              onChange={(e) => set("username", e.target.value)}
              placeholder="you@example.com"
            />
            <label>Password</label>
            <div className="row">
              <div style={{ flex: 1 }}>
                <PasswordField value={item.password} onChange={(v) => set("password", v)} />
              </div>
              <button type="button" className="ghost" onClick={() => set("password", generatePassword())}>
                Generate
              </button>
            </div>
            <label>2FA secret (TOTP)</label>
            <input
              value={item.totp}
              onChange={(e) => set("totp", e.target.value)}
              placeholder="base32 secret or otpauth:// URI from the site's 2FA setup"
              autoComplete="off"
              spellCheck={false}
            />
          </>
        )}

        {item.type === "card" && (
          <>
            <label>Cardholder</label>
            <input value={item.card.cardholder} onChange={(e) => setCard("cardholder", e.target.value)} placeholder="Name on the card" />
            <label>Card number</label>
            <input
              value={item.card.number}
              onChange={(e) => setCard("number", e.target.value)}
              placeholder="4111 1111 1111 1111"
              inputMode="numeric"
              autoComplete="off"
            />
            <div className="row">
              <div style={{ flex: 1 }}>
                <label>Expiry month</label>
                <input value={item.card.expMonth} onChange={(e) => setCard("expMonth", e.target.value)} placeholder="MM" inputMode="numeric" />
              </div>
              <div style={{ flex: 1 }}>
                <label>Expiry year</label>
                <input value={item.card.expYear} onChange={(e) => setCard("expYear", e.target.value)} placeholder="YYYY" inputMode="numeric" />
              </div>
              <div style={{ flex: 1 }}>
                <label>CVV</label>
                <input value={item.card.cvv} onChange={(e) => setCard("cvv", e.target.value)} placeholder="123" inputMode="numeric" autoComplete="off" />
              </div>
            </div>
          </>
        )}

        {item.type === "identity" && (
          <>
            <label>Full name</label>
            <input value={item.identity.fullName} onChange={(e) => setIdentity("fullName", e.target.value)} />
            <label>Email</label>
            <input value={item.identity.email} onChange={(e) => setIdentity("email", e.target.value)} />
            <label>Phone</label>
            <input value={item.identity.phone} onChange={(e) => setIdentity("phone", e.target.value)} />
            <label>Address</label>
            <textarea value={item.identity.address} onChange={(e) => setIdentity("address", e.target.value)} rows={2} />
            <label>Company</label>
            <input value={item.identity.company} onChange={(e) => setIdentity("company", e.target.value)} />
          </>
        )}

        {item.fields.length > 0 && <label>Custom fields</label>}
        {item.fields.map((f, i) => (
          <div className="cf-row" key={i}>
            <input
              value={f.label}
              onChange={(e) => setField(i, { label: e.target.value })}
              placeholder="Label"
              className="cf-label"
            />
            <input
              value={f.value}
              onChange={(e) => setField(i, { value: e.target.value })}
              placeholder="Value"
              className="cf-value"
              autoComplete="off"
            />
            <button
              type="button"
              className="icon-btn"
              title={f.hidden ? "Shown masked in details" : "Shown in the clear; click to mask"}
              aria-label={f.hidden ? "Unmask this field" : "Mask this field"}
              onClick={() => setField(i, { hidden: !f.hidden })}
            >
              <Icon name={f.hidden ? "eyeOff" : "eye"} size={16} />
            </button>
            <button
              type="button"
              className="icon-btn"
              title="Remove field"
              aria-label="Remove field"
              onClick={() => setItem((prev) => ({ ...prev, fields: prev.fields.filter((_, j) => j !== i) }))}
            >
              <Icon name="trash" size={16} />
            </button>
          </div>
        ))}
        <button
          type="button"
          className="ghost cf-add"
          onClick={() => setItem((prev) => ({ ...prev, fields: [...prev.fields, { label: "", value: "" }] }))}
        >
          + Add custom field
        </button>

        <label>Notes</label>
        <textarea value={item.notes} onChange={(e) => set("notes", e.target.value)} rows={item.type === "note" ? 6 : 3} />
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
  "session.revoke_all": "Signed out all devices",
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

function SecurityCheck(props: { items: VaultItem[]; onClose: () => void }) {
  const [breaches, setBreaches] = useState<Map<string, number> | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Local-only analysis; recomputed if the vault changes underneath.
  const weakById = useMemo(() => {
    const m = new Map<string, string>();
    for (const it of props.items) {
      const w = passwordWeakness(it.password);
      if (w) m.set(it.id, w);
    }
    return m;
  }, [props.items]);
  const reused = useMemo(() => reusedItemIds(props.items), [props.items]);

  async function runBreachCheck() {
    setError(null);
    setBusy(true);
    try {
      setBreaches(await breachedItemIds(props.items));
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  const withPasswords = props.items.filter((it) => it.password).length;
  const flagged = props.items.filter(
    (it) => weakById.has(it.id) || reused.has(it.id) || (breaches?.get(it.id) ?? 0) > 0,
  );

  return (
    <div className="modal-backdrop" onClick={props.onClose}>
      <div className="card modal" onClick={(e) => e.stopPropagation()}>
        <h2>Security check</h2>
        <p className="muted">
          Weak and reused passwords are detected here on your device. The breach check compares each password against
          the HaveIBeenPwned database by sending only a short, unrecoverable fragment of its hash — your passwords never
          leave this browser, and the passwd server is never involved.
        </p>

        <div className="row">
          <button className="ghost" disabled={busy || withPasswords === 0} onClick={runBreachCheck}>
            {busy
              ? "Checking..."
              : breaches
                ? "Re-check breaches"
                : `Check ${withPasswords} password${withPasswords === 1 ? "" : "s"} for breaches`}
          </button>
        </div>
        {error && <div className="error">{error}</div>}

        {flagged.length === 0 ? (
          <p className="muted">
            {withPasswords === 0 ? "No stored passwords to check yet." : "No weak or reused passwords found."}
            {breaches && withPasswords > 0 ? " No breached passwords either." : ""}
          </p>
        ) : (
          <ul className="activity-list">
            {flagged.map((it) => {
              const n = breaches?.get(it.id) ?? 0;
              return (
                <li key={it.id} className="activity-row health-row">
                  <span className="activity-label">{it.name || "(unnamed)"}</span>
                  <span className="health-badges">
                    {n > 0 && <span className="badge badge-danger">Breached &times;{n.toLocaleString()}</span>}
                    {reused.has(it.id) && <span className="badge badge-warn">Reused</span>}
                    {weakById.has(it.id) && <span className="badge badge-warn">{weakById.get(it.id)}</span>}
                  </span>
                </li>
              );
            })}
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

function ShareDialog(props: {
  session: Session;
  item: VaultItem;
  onClose: () => void;
  onShared: () => void;
}) {
  const [recipient, setRecipient] = useState("");
  const [error, setError] = useState<string | null>(null);

  return (
    <div className="modal-backdrop" onClick={props.onClose}>
      <div className="card modal" onClick={(e) => e.stopPropagation()}>
        <h2>Share "{props.item.name || "(unnamed)"}"</h2>
        <p className="muted">
          Enter the recipient's account identifier (their passphrase or email). The item is
          encrypted to their public key — only they can read it, and the server never can.
        </p>
        <label>Recipient identifier</label>
        <input
          value={recipient}
          onChange={(e) => setRecipient(e.target.value)}
          placeholder="their passphrase or email"
          autoComplete="off"
          spellCheck={false}
          autoFocus
        />
        {error && <div className="error">{error}</div>}
        <div className="row end">
          <button className="ghost" onClick={props.onClose}>
            Cancel
          </button>
          <AsyncButton
            variant="primary"
            loadingLabel="Sharing"
            successLabel="Shared"
            onClick={async () => {
              setError(null);
              if (!recipient.trim()) {
                setError("Enter a recipient identifier.");
                return false;
              }
              try {
                await shareItem(props.session, recipient.trim(), props.item);
                props.onShared();
                return true;
              } catch (e) {
                setError(errMsg(e) || "Could not share — check the recipient identifier.");
                return false;
              }
            }}
          >
            Share item
          </AsyncButton>
        </div>
      </div>
    </div>
  );
}

function SharedWithMe(props: {
  session: Session;
  onClose: () => void;
  onCopy: (label: string, value: string) => void;
}) {
  const [items, setItems] = useState<SharedItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  function reload() {
    listSharedWithMe(props.session)
      .then(setItems)
      .catch((e) => setError(errMsg(e)));
  }
  useEffect(reload, [props.session]);

  return (
    <div className="modal-backdrop" onClick={props.onClose}>
      <div className="card modal" onClick={(e) => e.stopPropagation()}>
        <h2>Shared with me</h2>
        <p className="muted">Items other people have shared with you, decrypted on this device.</p>
        {error && <div className="error">{error}</div>}
        {!items ? (
          <p className="muted">Loading...</p>
        ) : items.length === 0 ? (
          <p className="muted">Nothing has been shared with you yet.</p>
        ) : (
          <ul className="shared-list">
            {items.map((it) => (
              <li key={it.shareId} className="shared-row">
                <div className="shared-main">
                  <div className="item-name">{it.name || "(unnamed)"}</div>
                  <div className="item-sub">{itemSubtitle(it)}</div>
                </div>
                <div className="shared-actions">
                  {it.username && (
                    <button className="ghost" onClick={() => props.onCopy("username", it.username)}>
                      Copy user
                    </button>
                  )}
                  {it.password && (
                    <button className="ghost" onClick={() => props.onCopy("password", it.password)}>
                      Copy pass
                    </button>
                  )}
                  <AsyncButton
                    variant="ghost"
                    danger
                    loadingLabel="Removing"
                    onClick={async () => {
                      try {
                        await removeSharedItem(props.session, it.shareId);
                        reload();
                        return true;
                      } catch (e) {
                        setError(errMsg(e));
                        return false;
                      }
                    }}
                  >
                    Remove
                  </AsyncButton>
                </div>
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
