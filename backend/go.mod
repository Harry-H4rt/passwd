module github.com/passwd-app/server

go 1.22

// NOTE: intentionally zero external dependencies for Phase 0 (Go 1.22 std-lib
// routing). Phase 2 will add golang.org/x/crypto (argon2id) for the server-side
// password verifier and a JWT library — see docs/ROADMAP.md.
