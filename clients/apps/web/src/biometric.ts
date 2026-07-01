// Biometric unlock for the native mobile app. Every function is a safe no-op in
// the browser (guarded by Capacitor.isNativePlatform), and the plugin is loaded
// via dynamic import only on native, so it never lands in the web bundle's main
// path.
//
// Trade-off (the standard one for password-manager biometric unlock): when a
// user opts in, their master password is stored in the device's hardware-backed
// secure store (iOS Keychain / Android Keystore) and released only after a
// successful biometric check. The passwd server is never involved.
import { Capacitor } from "@capacitor/core";

const SERVER = "app.passwd.vault"; // keychain/keystore namespace for our credentials

export function isNative(): boolean {
  return Capacitor.isNativePlatform();
}

async function plugin() {
  const { NativeBiometric } = await import("@capgo/capacitor-native-biometric");
  return NativeBiometric;
}

// True only on a device with enrolled biometrics (fingerprint / face).
export async function biometricAvailable(): Promise<boolean> {
  if (!isNative()) return false;
  try {
    const r = await (await plugin()).isAvailable();
    return !!r.isAvailable;
  } catch {
    return false;
  }
}

// True if we've stored a master password for biometric unlock on this device.
export async function biometricEnrolled(): Promise<boolean> {
  if (!isNative()) return false;
  try {
    const c = await (await plugin()).getCredentials({ server: SERVER });
    return !!c?.password;
  } catch {
    return false;
  }
}

// Store the master password behind the device biometric (opt-in).
export async function enableBiometric(identifier: string, masterPassword: string): Promise<void> {
  if (!isNative()) return;
  await (await plugin()).setCredentials({ username: identifier, password: masterPassword, server: SERVER });
}

// Prompt for biometrics and return the stored credentials, or null if the user
// cancels / it fails / nothing is stored.
export async function unlockWithBiometric(): Promise<{ identifier: string; password: string } | null> {
  if (!isNative()) return null;
  try {
    const nb = await plugin();
    await nb.verifyIdentity({ title: "Unlock passwd", subtitle: "Confirm your identity", reason: "Unlock your vault" });
    const c = await nb.getCredentials({ server: SERVER });
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
    await (await plugin()).deleteCredentials({ server: SERVER });
  } catch {
    // nothing stored — fine
  }
}
