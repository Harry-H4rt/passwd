import { useEffect, useState } from "react";
import { masterPasswordIssue } from "@passwd/crypto";
import { Icon } from "./components/Icon";
import { PasswordField } from "./components/PasswordField";
import { ThemeToggle } from "./components/ThemeToggle";
import { VaultScreen } from "./VaultScreen";
import {
  type DesktopVault,
  type RecentVault,
  pickVaultToOpen,
  pickVaultToCreate,
  createNewVault,
  openExistingVault,
  readRecents,
  rememberRecent,
  clearRecents,
} from "./storage";

// Drop the in-memory vault (and its user key) after this much inactivity.
const IDLE_LOCK_MS = 10 * 60 * 1000;

type Screen =
  | { kind: "start" }
  | { kind: "unlock"; path: string }
  | { kind: "create"; path: string };

export function App() {
  const [vault, setVault] = useState<DesktopVault | null>(null);
  const [screen, setScreen] = useState<Screen>({ kind: "start" });

  // Idle auto-lock: any activity resets the timer; on expiry we discard the vault,
  // which clears the decrypted user key and items from memory.
  useEffect(() => {
    if (!vault) return;
    let timer: number;
    const lock = () => {
      setVault(null);
      setScreen({ kind: "start" });
    };
    const reset = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(lock, IDLE_LOCK_MS);
    };
    const events = ["mousemove", "mousedown", "keydown", "touchstart", "scroll"];
    events.forEach((e) => window.addEventListener(e, reset, { passive: true }));
    reset();
    return () => {
      window.clearTimeout(timer);
      events.forEach((e) => window.removeEventListener(e, reset));
    };
  }, [vault]);

  async function adopt(v: DesktopVault) {
    await rememberRecent(v.path);
    setVault(v);
  }

  if (vault) {
    return (
      <VaultScreen
        vault={vault}
        onChange={setVault}
        onLock={() => {
          setVault(null);
          setScreen({ kind: "start" });
        }}
      />
    );
  }
  if (screen.kind === "unlock") {
    return <Unlock path={screen.path} onBack={() => setScreen({ kind: "start" })} onOpened={adopt} />;
  }
  if (screen.kind === "create") {
    return <Create path={screen.path} onBack={() => setScreen({ kind: "start" })} onCreated={adopt} />;
  }
  return (
    <Start
      onOpen={(path) => setScreen({ kind: "unlock", path })}
      onNew={(path) => setScreen({ kind: "create", path })}
    />
  );
}

function Toolbar() {
  return (
    <div className="auth-toolbar">
      <ThemeToggle />
    </div>
  );
}

function Start(props: { onOpen: (path: string) => void; onNew: (path: string) => void }) {
  const [recents, setRecents] = useState<RecentVault[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    readRecents().then(setRecents);
  }, []);

  async function openDialog() {
    setError(null);
    const path = await pickVaultToOpen();
    if (path) props.onOpen(path);
  }
  async function newDialog() {
    setError(null);
    const path = await pickVaultToCreate();
    if (path) props.onNew(path);
  }

  return (
    <div className="center">
      <Toolbar />
      <div className="card auth">
        <div className="brand-row">
          <Icon name="lock" size={22} />
          <h1>passwd</h1>
        </div>
        <p className="muted">Offline vault. Your passwords stay in one encrypted file.</p>

        {recents.length > 0 && (
          <>
            <label>Recent vaults</label>
            <ul className="recent-list">
              {recents.map((r) => (
                <li key={r.path}>
                  <button className="recent-item" onClick={() => props.onOpen(r.path)} title={r.path}>
                    <Icon name="lock" size={16} />
                    <span className="recent-name">{r.name}</span>
                    <span className="recent-path">{r.path}</span>
                  </button>
                </li>
              ))}
            </ul>
            <button
              className="linklike"
              onClick={async () => {
                await clearRecents();
                setRecents([]);
              }}
            >
              Clear recent list
            </button>
          </>
        )}

        {error && <div className="error">{error}</div>}

        <div className="row">
          <button className="primary full" onClick={openDialog}>
            Open vault...
          </button>
          <button className="ghost full" onClick={newDialog}>
            New vault...
          </button>
        </div>
        <p className="fineprint">
          The vault is a single <code>.passwd</code> file you can keep anywhere, including a USB
          stick. There is no account, no server, and no password reset.
        </p>
      </div>
    </div>
  );
}

function Unlock(props: { path: string; onBack: () => void; onOpened: (v: DesktopVault) => void }) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      props.onOpened(await openExistingVault(props.path, password));
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="center">
      <Toolbar />
      <button className="back-link" onClick={props.onBack}>
        <Icon name="arrowLeft" size={16} />
        Back
      </button>
      <form className="card auth" onSubmit={submit}>
        <div className="brand-row">
          <Icon name="lock" size={22} />
          <h1>Unlock</h1>
        </div>
        <p className="muted ellipsis" title={props.path}>
          {props.path}
        </p>
        <label>Master password</label>
        <PasswordField value={password} onChange={setPassword} placeholder="your master password" />
        {error && <div className="error">{error}</div>}
        <button className="primary" disabled={busy} type="submit">
          {busy && <span className="spinner" />}
          <span>{busy ? "Unlocking" : "Unlock"}</span>
        </button>
      </form>
    </div>
  );
}

function Create(props: { path: string; onBack: () => void; onCreated: (v: DesktopVault) => void }) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const weak = masterPasswordIssue(password);
    if (weak) {
      setError(weak);
      return;
    }
    if (password !== confirm) {
      setError("The master passwords don't match.");
      return;
    }
    setBusy(true);
    try {
      props.onCreated(await createNewVault(props.path, password));
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="center">
      <Toolbar />
      <button className="back-link" onClick={props.onBack}>
        <Icon name="arrowLeft" size={16} />
        Back
      </button>
      <form className="card auth" onSubmit={submit}>
        <div className="brand-row">
          <Icon name="lock" size={22} />
          <h1>New vault</h1>
        </div>
        <p className="muted ellipsis" title={props.path}>
          {props.path}
        </p>
        <label>Master password</label>
        <PasswordField value={password} onChange={setPassword} placeholder="at least 12 characters" />
        <label>Confirm master password</label>
        <PasswordField value={confirm} onChange={setConfirm} placeholder="type it again" />
        {error && <div className="error">{error}</div>}
        <button className="primary" disabled={busy} type="submit">
          {busy && <span className="spinner" />}
          <span>{busy ? "Creating" : "Create vault"}</span>
        </button>
        <p className="fineprint">
          There is no recovery. If you lose this password the vault cannot be opened.
        </p>
      </form>
    </div>
  );
}

export function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : "Something went wrong.";
}
