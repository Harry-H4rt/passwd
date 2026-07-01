import { useEffect, useState } from "react";
import {
  type Session,
  registerAccount,
  loginAccount,
  loginWithPasskey,
  recoverAccount,
  newAccountId,
  TwoFactorRequiredError,
} from "@passwd/api-client";
import { masterPasswordIssue, normalizeIdentifier } from "@passwd/crypto";
import { biometricAvailable, biometricEnrolled, enableBiometric, unlockWithBiometric } from "./biometric";
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
  // Only for a typed email at registration: a re-entry to catch typos, since
  // there is no password reset and a mistyped handle locks the account out for
  // good. Blank/irrelevant for dice-generated passphrases.
  const [confirmId, setConfirmId] = useState("");
  // Forgot-master-password flow: prove possession of the recovery code, then set a
  // new master password. Lives inside login mode (toggled by a link).
  const [recover, setRecover] = useState(false);
  const [recoveryCode, setRecoveryCode] = useState("");
  // Non-null once a first sign-in attempt reports a second factor is required; it
  // holds the enrolled methods so we can offer a passkey, a TOTP code, or both.
  const [twoFactor, setTwoFactor] = useState<{ methods: string[] } | null>(null);
  const [totp, setTotp] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Native biometric unlock (mobile only; all no-ops in the browser).
  const [bioAvailable, setBioAvailable] = useState(false);
  const [bioEnrolled, setBioEnrolled] = useState(false);
  const [bioRemember, setBioRemember] = useState(false);
  const [bioBusy, setBioBusy] = useState(false);

  const needTotp = !!twoFactor?.methods.includes("totp");
  const canPasskey = !!twoFactor?.methods.includes("webauthn");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const avail = await biometricAvailable();
      const enrolled = avail && (await biometricEnrolled());
      if (!cancelled) {
        setBioAvailable(avail);
        setBioEnrolled(enrolled);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // Store the master password behind the device biometric when opted in, then
  // hand off. enableBiometric is a no-op off native, so this is browser-safe.
  async function afterAuth(s: Session) {
    if (bioRemember && identifier.trim() && password) {
      try {
        await enableBiometric(identifier.trim(), password);
      } catch {
        // biometric enrollment is best-effort; don't block sign-in
      }
    }
    props.onAuthed(s);
  }

  // Unlock via fingerprint/face: retrieve the stored master password behind a
  // biometric prompt, then run the normal login (honoring 2FA if enrolled).
  async function unlockBio() {
    setError(null);
    setBioBusy(true);
    try {
      const creds = await unlockWithBiometric();
      if (!creds) return; // cancelled or unavailable
      try {
        props.onAuthed(await loginAccount(creds.identifier, creds.password));
      } catch (err) {
        if (err instanceof TwoFactorRequiredError) {
          setIdentifier(creds.identifier);
          setPassword(creds.password);
          setMode("login");
          setTwoFactor({ methods: err.methods });
          return;
        }
        setError(err instanceof Error ? err.message : "Biometric unlock failed.");
      }
    } finally {
      setBioBusy(false);
    }
  }

  function generate() {
    setIdentifier(newAccountId());
    setGenerated(true);
    setConfirmId("");
  }

  function switchMode(next: "register" | "login") {
    setMode(next);
    setError(null);
    setTwoFactor(null);
    setTotp("");
    setRecover(false);
    setRecoveryCode("");
    setConfirmId("");
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (recover) {
      if (!identifier.trim() || !recoveryCode.trim()) {
        setError("Enter your identifier and recovery code.");
        return;
      }
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
        await afterAuth(await recoverAccount(identifier, recoveryCode, password));
      } catch {
        setError("Recovery failed. Double-check your identifier and recovery code.");
      } finally {
        setBusy(false);
      }
      return;
    }
    if (!identifier.trim() || !password) {
      setError("Enter an account identifier and a master password.");
      return;
    }
    if (mode === "register") {
      // A typed email (not a dice passphrase) is the only handle a user can
      // fat-finger; verify it here since there is no reset if it's wrong.
      if (!generated && identifier.includes("@")) {
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(identifier.trim())) {
          setError("That doesn't look like a valid email. Check it, or roll the dice for a private passphrase.");
          return;
        }
        if (normalizeIdentifier(identifier) !== normalizeIdentifier(confirmId)) {
          setError("The email addresses don't match.");
          return;
        }
      }
      const weak = masterPasswordIssue(password);
      if (weak) {
        setError(weak);
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
        await afterAuth(s);
      } else {
        await afterAuth(await loginAccount(identifier, password, needTotp ? totp : undefined));
      }
    } catch (err) {
      if (err instanceof TwoFactorRequiredError) {
        setTwoFactor({ methods: err.methods });
        return;
      }
      setError(err instanceof Error ? err.message : "Something went wrong.");
    } finally {
      setBusy(false);
    }
  }

  // Completes a passkey sign-in. Separate from the form submit because it runs the
  // WebAuthn ceremony (a device prompt) rather than verifying a typed code.
  async function usePasskey() {
    setError(null);
    if (!identifier.trim() || !password) {
      setError("Enter your identifier and master password first.");
      return;
    }
    setBusy(true);
    try {
      await afterAuth(await loginWithPasskey(identifier, password));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong.");
    } finally {
      setBusy(false);
    }
  }

  const submitLabel = busy
    ? recover
      ? "Recovering"
      : "Deriving keys"
    : recover
      ? "Recover and unlock"
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

        {bioEnrolled && !recover && !twoFactor && (
          <>
            <button type="button" className="ghost full" disabled={bioBusy} onClick={unlockBio}>
              <Icon name="lock" size={16} />
              <span>{bioBusy ? "Unlocking..." : "Unlock with biometrics"}</span>
            </button>
            <div className="or-divider">or</div>
          </>
        )}

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

        {mode === "register" && !generated && identifier.includes("@") && (
          <>
            <label>Confirm email</label>
            <input
              value={confirmId}
              onChange={(e) => setConfirmId(e.target.value)}
              placeholder="type your email again"
              autoComplete="off"
              spellCheck={false}
              inputMode="email"
            />
            <p className="hint">There is no password reset, so a typo here locks the account out for good. We never send email or store it in the clear.</p>
          </>
        )}

        {recover && (
          <>
            <label>Recovery code</label>
            <textarea
              className="recovery-input"
              value={recoveryCode}
              onChange={(e) => setRecoveryCode(e.target.value)}
              placeholder="your 24-word recovery code"
              rows={3}
              autoComplete="off"
              spellCheck={false}
            />
          </>
        )}

        <label>{recover ? "New master password" : "Master password"}</label>
        <PasswordField
          value={password}
          onChange={setPassword}
          placeholder={recover ? "choose a new master password" : "never sent to the server"}
        />

        {(mode === "register" || recover) && (
          <>
            <label>Confirm {recover ? "new " : ""}master password</label>
            <PasswordField value={confirm} onChange={setConfirm} placeholder="type it again" />
          </>
        )}

        {mode === "login" && !twoFactor && !recover && (
          <button
            type="button"
            className="linklike"
            onClick={() => {
              setRecover(true);
              setError(null);
              setConfirm("");
            }}
          >
            Forgot your master password? Recover with a recovery code
          </button>
        )}
        {recover && (
          <button
            type="button"
            className="linklike"
            onClick={() => {
              setRecover(false);
              setError(null);
              setRecoveryCode("");
            }}
          >
            Back to sign in
          </button>
        )}

        {mode === "login" && twoFactor && (
          <div className="twofactor">
            <p className="muted">Finish signing in with your second factor.</p>
            {canPasskey && (
              <button type="button" className="ghost full" disabled={busy} onClick={usePasskey}>
                <Icon name="lock" size={16} />
                <span>Use a passkey</span>
              </button>
            )}
            {canPasskey && needTotp && <div className="or-divider">or</div>}
            {needTotp && (
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
          </div>
        )}

        {bioAvailable && !recover && !twoFactor && (
          <label className="bio-check">
            <input type="checkbox" checked={bioRemember} onChange={(e) => setBioRemember(e.target.checked)} />
            <span>Unlock with biometrics on this device next time</span>
          </label>
        )}

        {error && <div className="error">{error}</div>}

        {/* Hide the form submit when the only way to finish is a passkey (its own button). */}
        {(mode === "register" || !twoFactor || needTotp) && (
          <button className="primary" disabled={busy} type="submit">
            {busy && <span className="spinner" />}
            <span>{submitLabel}</span>
          </button>
        )}

        <p className="fineprint">
          Your master password and identifier never leave this device in plaintext. There is no
          password reset; only a recovery code you set up yourself can get you back in, so keep it
          and your identifier safe.
        </p>
      </form>
    </div>
  );
}
