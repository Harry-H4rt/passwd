import { useState } from "react";
import { type Session, registerAccount, loginAccount, newAccountId } from "@passwd/api-client";
import { VaultScreen } from "./VaultScreen";

export function App() {
  const [session, setSession] = useState<Session | null>(null);
  // The generated passphrase to show once, right after sign-up.
  const [recovery, setRecovery] = useState<string | null>(null);

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
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function generate() {
    setIdentifier(newAccountId());
    setGenerated(true);
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!identifier.trim() || !password) {
      setError("Enter an account identifier and a master password.");
      return;
    }
    if (mode === "register" && password.length < 8) {
      setError("Master password must be at least 8 characters.");
      return;
    }
    setBusy(true);
    try {
      if (mode === "register") {
        const s = await registerAccount(identifier, password);
        props.onRecovery(generated ? identifier.trim().toLowerCase() : null);
        props.onAuthed(s);
      } else {
        props.onAuthed(await loginAccount(identifier, password));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="center">
      <form className="card auth" onSubmit={submit}>
        <h1>
          passwd <span className="lock">🔒</span>
        </h1>
        <p className="muted">Zero-knowledge password manager</p>

        <div className="tabs">
          <button type="button" className={mode === "register" ? "active" : ""} onClick={() => setMode("register")}>
            Create account
          </button>
          <button type="button" className={mode === "login" ? "active" : ""} onClick={() => setMode("login")}>
            Sign in
          </button>
        </div>

        <label>Account identifier</label>
        <input
          value={identifier}
          onChange={(e) => {
            setIdentifier(e.target.value);
            setGenerated(false);
          }}
          placeholder={mode === "register" ? "generate a passphrase, or use an email" : "your passphrase or email"}
          autoComplete="off"
          spellCheck={false}
        />
        {mode === "register" && (
          <button type="button" className="link" onClick={generate}>
            ✨ Generate a private passphrase (recommended — no email needed)
          </button>
        )}

        <label>Master password</label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="never sent to the server"
          autoComplete="off"
        />

        {error && <div className="error">{error}</div>}

        <button className="primary" disabled={busy} type="submit">
          {busy ? "Deriving keys…" : mode === "register" ? "Create account" : "Unlock vault"}
        </button>

        <p className="fineprint">
          Your master password and identifier never leave this device in plaintext. There is{" "}
          <strong>no password reset</strong> — if you lose them, the vault is unrecoverable.
        </p>
      </form>
    </div>
  );
}
