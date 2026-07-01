# passwd mobile (Capacitor)

The mobile app is the **web vault running inside a native WebView**. It reuses
the exact same code as `apps/web` — including the WebCrypto + `hash-wasm`
Argon2id crypto and the `@passwd/api-client` — so nothing security-critical is
re-implemented for mobile. The native shell just hosts the web app and (later)
adds mobile-native capabilities (biometric unlock, secure token storage,
autofill).

## Why Capacitor

`@passwd/crypto` uses `crypto.subtle` (AES-GCM) and a WebAssembly Argon2id, both
of which run in a mobile WebView. That lets the audited web crypto ship on
mobile untouched, instead of porting it to a native runtime.

## Prerequisites

- Node 20+ and `npm install` at the repo/clients root.
- **Android:** Android Studio with the SDK (sets `ANDROID_HOME`).
- **iOS:** a **Mac** with Xcode and CocoaPods (`sudo gem install cocoapods`).
  iOS cannot be built on Linux/Windows.

## First-time setup

From the repo root:

```bash
# 1. Build the web vault and generate the native projects (one time each).
./scripts/mobile.sh sync            # builds web -> apps/mobile/www, runs cap sync
npm -w @passwd/mobile run add:android
npm -w @passwd/mobile run add:ios   # Mac only

# 2. Open in the native IDE and run on a simulator/device.
./scripts/mobile.sh android         # builds, syncs, opens Android Studio
./scripts/mobile.sh ios             # Mac only: opens Xcode
```

`cap add` scaffolds the `android/` and `ios/` project folders. They're
git-ignored for now (regenerable from `capacitor.config.ts`); start committing
them once you customize them (icons, permissions, native autofill) so that work
is versioned.

## Backend / CORS

Requests originate from `https://localhost` (Android) and `capacitor://localhost`
(iOS). Both are in the backend's `PASSWD_ALLOWED_ORIGINS` (see `render.yaml`), so
the API accepts them. If you point the app at a different backend, add those two
origins there too.

Passkeys (WebAuthn) don't work inside a plain WebView, so mobile falls back to
password + TOTP, exactly like the extension. That's unchanged from the web vault.

## Before publishing

- Set a real reverse-DNS `appId` in `capacitor.config.ts` (it's hard to change
  later; app links and passkeys bind to it).
- Add app icons / splash screens (`@capacitor/assets`).
- Wire biometric unlock and secure storage (Phase 2), then native autofill
  (Phase 3) — see the roadmap.
