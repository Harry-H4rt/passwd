# Contributing

Thanks for your interest in passwd. This guide covers local setup, the workflow,
and the conventions the project follows.

> Found a security vulnerability? Do **not** open a public issue — see
> [`SECURITY.md`](SECURITY.md) for private reporting.

## Prerequisites

- **Go** 1.22.x (backend)
- **Node** 20+ and **npm** 10+ (clients and site)
- For the desktop app only: the **Rust** toolchain and the Tauri system libraries
  (see the [README](README.md#desktop-app-standalone-and-offline))

## Project layout

See [`README.md`](README.md#repository-layout) for the full map. In short: a Go
backend (`backend/`), a TypeScript monorepo of clients (`clients/`, npm
workspaces), an Astro site (`site/`), and design/architecture docs (`docs/`).

## Setup and run

```bash
# Backend API on :8080 (in-memory store; omit PASSWD_DB for SQLite)
cd backend && PASSWD_DB=memory go run ./cmd/server

# Web vault on :5173 (separate terminal)
cd clients && npm install && npm -w @passwd/web run dev
```

## Before you open a pull request

Run the same checks CI runs and make sure they pass:

```bash
# Backend
cd backend && go vet ./... && go test ./... && gofmt -l ./internal ./cmd

# Clients
cd clients && npm ci \
  && npm run typecheck --workspaces --if-present \
  && npm test --workspaces --if-present \
  && npm run build -w @passwd/web \
  && npm run build -w @passwd/extension
```

- `gofmt -l` should print nothing (run `gofmt -w` to fix formatting).
- Add or update tests for behavior changes. Crypto changes must keep the shared
  known-answer vectors (`docs/test-vectors.json`) passing in **both** the TS and Go
  implementations.

## Conventions

- **Cryptography:** never let a plaintext secret, master password, or master key
  reach the server. Client-side crypto lives only in `@passwd/crypto`; the server
  must never import it. Read [`docs/CRYPTO.md`](docs/CRYPTO.md) before touching
  anything in this area, and prefer discussing the design in an issue first.
- **Privacy:** the server stores no PII — no plaintext identifier, no item
  metadata, and nothing user-identifying in logs. Keep it that way.
- **Style:** match the surrounding code; keep functions small and commented where
  intent isn't obvious. Go code is `gofmt`-clean; TypeScript is type-checked.
- **Commits:** clear, imperative subject lines (e.g. "Add audit log endpoint").
  Keep a change focused; update the relevant docs in the same PR.

## Pull requests

1. Fork and create a feature branch.
2. Make the change with tests and docs.
3. Ensure all checks above pass.
4. Open a PR against `main` describing the change and its rationale. Link any
   related issue.

Maintainers merge with a non-fast-forward merge to keep history readable.
