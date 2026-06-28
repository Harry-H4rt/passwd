# @passwd/api-client (stub — Phase 0)

Typed HTTP client shared by the web vault and extension. Wraps the Go backend's
endpoints (see [`../../../docs/ARCHITECTURE.md`](../../../docs/ARCHITECTURE.md))
and is responsible only for transport — it sends/receives the ciphertext produced
by `@passwd/crypto` and never handles plaintext secrets.

**Next (Phase 0/2):** generate or hand-write typed methods for
`prelogin`, `register`, `login`, `refresh`, `sync`, and cipher CRUD, with token
storage and refresh handling.
