# web vault (stub — Phase 3)

The browser-based vault SPA. **Not Wasp** — a plain Vite + React app so it can
share `@passwd/crypto` and `@passwd/api-client` with the extension.

## Scaffold it (Phase 3)

```bash
cd clients/apps
npm create vite@latest web -- --template react-ts   # (merge into this folder)
```

Then wire screens: register → unlock → vault list → item CRUD, with auto-lock
that clears the in-memory user key. All encryption happens via `@passwd/crypto`
before anything touches the network.
