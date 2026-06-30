# Security Policy

passwd is an end-to-end-encrypted password manager. Security reports are very
welcome and taken seriously.

> **Project status: pre-audit.** The cryptographic design (see
> [`docs/CRYPTO.md`](docs/CRYPTO.md)) is documented and has had an internal review
> (see [`docs/SECURITY-REVIEW.md`](docs/SECURITY-REVIEW.md)), but it has **not** had
> an independent third-party audit. Do not store irreplaceable secrets in it yet.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately through GitHub's **[Private vulnerability reporting](https://github.com/Harry-H4rt/passwd/security/advisories/new)**
(the "Report a vulnerability" button under the repository's **Security** tab). This
keeps the report confidential until a fix is available and lets us collaborate on a
coordinated disclosure.

When reporting, please include:

- the affected component (backend, web vault, extension, desktop app, or
  `@passwd/crypto`) and version/commit,
- a description of the issue and its impact,
- steps to reproduce or a proof of concept, and
- any suggested remediation, if you have one.

We aim to acknowledge a report within a few days and to keep you updated as we
investigate and fix. With your agreement we will credit you once a fix ships.

## Scope

Especially valuable areas:

- the cryptographic design and its implementation in `@passwd/crypto` and the Go
  reference (`backend/internal/crypto`);
- anything that would let the server, a network attacker, or a database thief learn
  a master password, a vault item, or the plaintext account identifier;
- authentication, session, 2FA, and account-recovery flows;
- cross-account access (one user reading or modifying another's data).

Out of scope (consistent with the documented threat model):

- a fully compromised client device or browser/OS with a keylogger;
- attacks requiring a malicious browser extension already installed by the user;
- denial of service from traffic volume alone;
- findings that depend on running with the insecure development defaults (the
  server refuses to start in production with them).

## Supported versions

The project is pre-1.0 and moves fast; only the latest `main` (and the most recent
release) receives security fixes.
