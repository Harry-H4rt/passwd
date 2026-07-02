// Biometric unlock for the native mobile app. Every function is a safe no-op in
// the browser (guarded by Capacitor.isNativePlatform).
//
// The plugin is imported statically on purpose: its JS side is a tiny
// registerPlugin() wrapper (@capacitor/core is in the main bundle anyway), and
// loading it as a lazy chunk hangs forever inside the Capacitor WebView --
// Vite's preload helper waits on a modulepreload event that never fires under
// the app shell's https://localhost scheme (found via the 0.1.5 on-screen
// diagnostic: "import=timeout").
//
// Trade-off (the standard one for password-manager biometric unlock): when a
// user opts in, their master password is stored in the device's hardware-backed
// secure store (iOS Keychain / Android Keystore) and released only after a
// successful biometric check. The passwd server is never involved.
import { Capacitor } from "@capacitor/core";
import { NativeBiometric } from "@capgo/capacitor-native-biometric";

const SERVER = "app.passwd.vault"; // keychain/keystore namespace for our credentials

export function isNative(): boolean {
  return Capacitor.isNativePlatform();
}

// True when running inside the mobile app's WebView, judged by the serving
// origin rather than the Capacitor bridge. The Android shell serves from
// https://localhost and iOS from capacitor://localhost, so this stays true even
// if bridge injection failed (exactly the case the diagnostic must catch);
// browsers and the dev server (http:, or a port) never match.
export function isAppShell(): boolean {
  return (
    isNative() ||
    window.location.origin === "https://localhost" ||
    window.location.origin === "capacitor://localhost"
  );
}

function msg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

async function withTimeout<T>(p: Promise<T>, ms: number): Promise<T | "timeout"> {
  return Promise.race([p, new Promise<"timeout">((res) => setTimeout(() => res("timeout"), ms))]);
}

// Debug helper: reports why biometrics are (un)available, step by step via
// onStep so a hung native call still leaves the completed steps visible.
// Shown as small text on the sign-in screen inside the app shell only.
export async function biometricDiagnostic(onStep: (line: string) => void): Promise<void> {
  const parts: string[] = [];
  const push = (s: string) => {
    parts.push(s);
    onStep(parts.join(" | "));
  };
  push(`build=${import.meta.env.VITE_BUILD_STAMP ?? "dev"}`);
  push(`bridge=${typeof (window as { Capacitor?: unknown }).Capacitor !== "undefined"}`);
  push(`platform=${Capacitor.getPlatform()}`);
  push(`plugin=${Capacitor.isPluginAvailable("NativeBiometric")}`);
  try {
    const r = await withTimeout(NativeBiometric.isAvailable(), 4000);
    if (r === "timeout") {
      push("isAvailable=timeout");
      return;
    }
    const rec = r as unknown as Record<string, unknown>;
    push(`isAvailable=${rec.isAvailable} type=${rec.biometryType} err=${rec.errorCode ?? rec.code ?? "none"}`);
  } catch (e) {
    push("isAvailable threw: " + msg(e));
  }
}

// True only on a device with enrolled biometrics (fingerprint / face).
export async function biometricAvailable(): Promise<boolean> {
  if (!isNative()) return false;
  try {
    const r = await NativeBiometric.isAvailable();
    return !!r.isAvailable;
  } catch {
    return false;
  }
}

// True if we've stored a master password for biometric unlock on this device.
export async function biometricEnrolled(): Promise<boolean> {
  if (!isNative()) return false;
  try {
    const c = await NativeBiometric.getCredentials({ server: SERVER });
    return !!c?.password;
  } catch {
    return false;
  }
}

// Store the master password behind the device biometric (opt-in).
export async function enableBiometric(identifier: string, masterPassword: string): Promise<void> {
  if (!isNative()) return;
  await NativeBiometric.setCredentials({ username: identifier, password: masterPassword, server: SERVER });
}

// Prompt for biometrics and return the stored credentials, or null if the user
// cancels / it fails / nothing is stored.
export async function unlockWithBiometric(): Promise<{ identifier: string; password: string } | null> {
  if (!isNative()) return null;
  try {
    await NativeBiometric.verifyIdentity({ title: "Unlock passwd", subtitle: "Confirm your identity", reason: "Unlock your vault" });
    const c = await NativeBiometric.getCredentials({ server: SERVER });
    if (!c?.password) return null;
    return { identifier: c.username, password: c.password };
  } catch {
    return null;
  }
}

// Forget the stored master password (disable biometric unlock on this device).
export async function disableBiometric(): Promise<void> {
  if (!isNative()) return;
  try {
    await NativeBiometric.deleteCredentials({ server: SERVER });
  } catch {
    // nothing stored -- fine
  }
}
