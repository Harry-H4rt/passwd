# @passwd/extension

The browser extension: a Manifest V3 popup built with [WXT](https://wxt.dev)
(Vite-based, React) that targets Chrome and Firefox from one codebase. It reuses
`@passwd/crypto` and `@passwd/api-client`, so encryption happens in the extension
and the backend only ever sees ciphertext.

## Features

- Unlock with your identifier and master password; the unlocked session persists
  across popup opens (`chrome.storage.session`) and auto-locks when idle.
- Vault list with search; view and copy username/password; add, edit, and delete
  items from the popup.
- Autofill with strict domain matching to resist phishing.
- Save-on-submit detection: when you log in to a site, the popup offers to save the
  new credentials.
- TOTP second factor at sign-in. (Passkey login is web-vault only, because a
  passkey bound to the vault's relying-party ID cannot be asserted from the
  extension's `chrome-extension://` origin.)
- Deterministic monogram avatars — no remote favicon fetches.

## Develop and build

Run from the `clients/` workspace root:

```bash
cd clients
npm install
npm -w @passwd/extension run dev            # Chrome dev with live reload
npm -w @passwd/extension run dev:firefox    # Firefox dev with live reload
npm -w @passwd/extension run build          # Chrome  -> apps/extension/.output/chrome-mv3
npm -w @passwd/extension run build:firefox  # Firefox -> apps/extension/.output/firefox-mv2
```

## Load an unpacked build

- **Chrome:** `chrome://extensions` → enable **Developer mode** → **Load unpacked**
  → select `apps/extension/.output/chrome-mv3`.
- **Firefox:** `about:debugging#/runtime/this-firefox` → **Load Temporary Add-on…**
  → select `apps/extension/.output/firefox-mv2/manifest.json`.

The backend host the extension talks to is configured at build time via
`WXT_API_BASE` (and `WXT_VAULT_URL` for the "open vault" link); see `.env.example`.
Publishing to the Chrome Web Store and AMO is documented in
[`docs/DEPLOYMENT.md`](../../../docs/DEPLOYMENT.md).
