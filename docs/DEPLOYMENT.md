# Deployment & publishing

> ⚠️ Pre-audit. Do not host this for real users until the Phase 5 security audit
> gate passes (see ROADMAP). The steps below are the mechanics for when it does.

## Backend (production)

Set strong, **stable** secrets — the server refuses to boot in production with the
dev defaults:

| Env var | Notes |
|---|---|
| `PASSWD_ENV=production` | enables HSTS; enforces non-default secrets |
| `PASSWD_JWT_SECRET` | `openssl rand -hex 32` |
| `PASSWD_IDENTIFIER_PEPPER` | `openssl rand -hex 32` — **never change it** (rotating orphans all accounts) |
| `PASSWD_DB` | persistent path, e.g. `/var/lib/passwd/passwd.db` |
| `PASSWD_ALLOWED_ORIGINS` | your web-vault origin, e.g. `https://vault.example.com` |
| `PASSWD_ADDR` | listen address |

Terminate TLS in front of it (reverse proxy / load balancer). Build a static
binary: `cd backend && go build -o passwd-server ./cmd/server` (pure-Go SQLite, no
cgo). Back up the DB file; it holds only ciphertext + verifiers.

## Web vault (production)

`cd clients && npm -w @passwd/web run build` → static files in
`apps/web/dist`. Host them on any static host/CDN. Two options for the API:
- **Same-origin (simplest):** serve the API under the same host as the SPA (reverse
  proxy `/api` → backend); no CORS needed.
- **Separate origin:** point the SPA at the API origin and add that SPA origin to
  `PASSWD_ALLOWED_ORIGINS`.

> Today the API base is same-origin (`""`) in the web app and a hardcoded
> `http://localhost:8080` in the extension. For production, wire these to a build-
> time env (`import.meta.env`) — tracked in the roadmap.

## Publishing the browser extension

Build distributable zips (WXT):

```bash
cd clients
npm -w @passwd/extension run zip          # -> .output/<name>-<ver>-chrome.zip
npm -w @passwd/extension run zip:firefox  # -> .output/<name>-<ver>-firefox.zip (+ sources zip)
```

Before publishing: set a **real, permanent** Gecko id in `wxt.config.ts`
(`browser_specific_settings.gecko.id`, e.g. `passwd@yourdomain.com`) and point
`host_permissions` / the API base at your production API domain (not localhost).

### Firefox — addons.mozilla.org (AMO)

1. Create a Firefox account and sign in to <https://addons.mozilla.org/developers/>.
2. **Submit a New Add-on** → upload the `*-firefox.zip`. Because the source is
   bundled/minified, also upload the **sources zip** WXT generates (AMO requires
   reviewable source for bundled add-ons).
3. Choose distribution:
   - **On this site (listed):** AMO reviews + signs, and it's listed on
     addons.mozilla.org for anyone to install.
   - **On your own (self-distribution):** AMO signs and returns a signed `.xpi`
     you host yourself; users install it directly.
4. Fill in listing metadata (description, icons, screenshots, privacy policy —
   emphasize zero-knowledge) and submit. Review can take from minutes to days.
5. CI alternative: `web-ext sign` (web-ext ships with WXT) using an AMO API
   key/secret from the Developer Hub to sign without the web UI.

Notes: an **unsigned** add-on can only be loaded temporarily (`about:debugging`)
or in Firefox Developer/Nightly editions; release Firefox requires a signed,
AMO-issued build. We build Firefox as MV2 today (`.output/firefox-mv2`); Firefox
MV3 is an option later.

### Chrome — Chrome Web Store

1. Register at the [Chrome Web Store Developer Dashboard](https://chrome.google.com/webstore/devconsole)
   (one-time US$5 fee).
2. **Add new item** → upload the `*-chrome.zip` (MV3).
3. Fill in listing + privacy disclosures and submit for review.

(Edge uses the same MV3 zip via Partner Center; Safari needs a separate
`safari-web-extension-converter` step — out of scope for now.)
