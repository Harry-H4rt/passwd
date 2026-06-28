import { useEffect, useState } from "react";
import {
  type Session,
  registerAccount,
  loginAccount,
  newAccountId,
  TwoFactorRequiredError,
} from "@passwd/api-client";
import { VaultScreen } from "./VaultScreen";
import { Icon } from "./components/Icon";
import { PasswordField } from "./components/PasswordField";
import { ThemeToggle } from "./components/ThemeToggle";

// Lock (drop the in-memory user key) after this much inactivity.
const IDLE_LOCK_MS = 15 * 60 * 1000;

// Marketing site, for the "back to site" link. Override with VITE_SITE_URL.
const SITE_URL = import.meta.env.VITE_SITE_URL ?? "http://localhost:4321";

export function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [recovery, setRecovery] = useState<string | null>(null);

  // Auto-lock on idle: any activity resets a timer; on expiry we clear the
  // session, which discards the decrypted user key from memory.
  useEffect(() => {
    if (!session) return;
    let timer: number;
    const lock = () => {
      setRecovery(null);
      setSession(null);
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
  }, [session]);

  if (session) {
    return (
      <VaultScreen
        session={session}
        recovery={recovery}
        onDismissRecovery={() => setRecovery(null)}
        onLock={() => {
          setRecovery(null);
          setSession(null);
        }}
      />
    );
  }
  return <AuthScreen onAuthed={setSession} onRecovery={setRecovery} />;
}

function AuthScreen(props: {
  onAuthed: (s: Session) => void;
  onRecovery: (phrase: string | null) => void;
}) {
  const [mode, setMode] = useState<"register" | "login">("register");
  const [identifier, setIdentifier] = useState("");
  const [generated, setGenerated] = useState(false);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [needTotp, setNeedTotp] = useState(false);
  const [totp, setTotp] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function generate() {
    setIdentifier(newAccountId());
    setGenerated(true);
  }

  function switchMode(next: "register" | "login") {
    setMode(next);
    setError(null);
    setNeedTotp(false);
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!identifier.trim() || !password) {
      setError("Enter an account identifier and a master password.");
      return;
    }
    if (mode === "register") {
      if (password.length < 8) {
        setError("Master password must be at least 8 characters.");
        return;
      }
      if (password !== confirm) {
        setError("The master passwords don't match.");
        return;
      }
    }
    setBusy(true);
    try {
      if (mode === "register") {
        const s = await registerAccount(identifier, password);
        props.onRecovery(generated ? identifier.trim().toLowerCase() : null);
        props.onAuthed(s);
      } else {
        props.onAuthed(await loginAccount(identifier, password, needTotp ? totp : undefined));
      }
    } catch (err) {
      if (err instanceof TwoFactorRequiredError) {
        setNeedTotp(true);
        return;
      }
      setError(err instanceof Error ? err.message : "Something went wrong.");
    } finally {
      setBusy(false);
    }
  }

  const submitLabel = busy
    ? "Deriving keys"
    : mode === "register"
      ? "Create account"
      : needTotp
        ? "Verify and unlock"
        : "Unlock vault";

  return (
    <div className="center">
      <div className="auth-toolbar">
        <ThemeToggle />
      </div>
      <a className="back-link" href={SITE_URL}>
        <Icon name="arrowLeft" size={16} />
        Back to site
      </a>
      <form className="card auth" onSubmit={submit}>
        <div className="brand-row">
          <Icon name="lock" size={22} />
          <h1>passwd</h1>
        </div>
        <p className="muted">Zero-knowledge password manager</p>

        <div className="tabs">
          <button type="button" className={mode === "register" ? "active" : ""} onClick={() => switchMode("register")}>
            Create account
          </button>
          <button type="button" className={mode === "login" ? "active" : ""} onClick={() => switchMode("login")}>
            Sign in
          </button>
        </div>

        <label>Account identifier</label>
        <div className="pwfield">
          <input
            value={identifier}
            onChange={(e) => {
              setIdentifier(e.target.value);
              setGenerated(false);
            }}
            placeholder={mode === "register" ? "roll the dice, or use an email" : "your passphrase or email"}
            autoComplete="off"
            spellCheck={false}
          />
          {mode === "register" && (
            <button
              type="button"
              className="reveal icon-only"
              onClick={generate}
              aria-label="Generate a private passphrase"
              title="Generate a private passphrase"
            >
              <Icon name="dice" size={18} />
            </button>
          )}
        </div>
        {mode === "register" && (
          <p className="hint">Roll the dice for a private passphrase, or type your own email. No email needed.</p>
        )}

        <label>Master password</label>
        <PasswordField value={password} onChange={setPassword} placeholder="never sent to the server" />

        {mode === "register" && (
          <>
            <label>Confirm master password</label>
            <PasswordField value={confirm} onChange={setConfirm} placeholder="type it again" />
          </>
        )}

        {mode === "login" && needTotp && (
          <>
            <label>Two-factor code</label>
            <input
              value={totp}
              onChange={(e) => setTotp(e.target.value)}
              placeholder="6-digit code"
              inputMode="numeric"
              autoComplete="one-time-code"
              autoFocus
            />
          </>
        )}

        {error && <div className="error">{error}</div>}

        <button className="primary" disabled={busy} type="submit">
          {busy && <span className="spinner" />}
          <span>{submitLabel}</span>
        </button>

        <p className="fineprint">
          Your master password and identifier never leave this device in plaintext. There is no
          password reset, so if you lose them the vault is unrecoverable.
        </p>
      </form>
    </div>
  );
}
