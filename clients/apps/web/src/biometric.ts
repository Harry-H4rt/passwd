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
