# browser extension (stub — Phase 4)

Manifest V3 extension built with [WXT](https://wxt.dev) (Vite-based, React,
cross-browser). Reuses `@passwd/crypto` and `@passwd/api-client`.

## Scaffold it (Phase 4)

```bash
cd clients/apps
npx wxt@latest init extension   # choose the React template; merge into this folder
```

Key features to build: popup vault + unlock, search, **autofill with strict
domain matching** (anti-phishing), and save-on-submit detection. Target Chrome
and Firefox from the one codebase.
