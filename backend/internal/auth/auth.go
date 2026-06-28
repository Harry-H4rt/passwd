// Package auth holds authentication policy: default KDF parameters the client
// should use, and (Phase 2) the server-side password verifier and token issuing.
//
// Reminder on the zero-knowledge contract: the server receives the client's
// "master password hash" only as a login credential, then stores
// Argon2id(masterPasswordHash, randomSalt). It never sees the master password or
// the master key. See docs/CRYPTO.md.
package auth

import "github.com/passwd-app/server/internal/storage"

// DefaultKDF is what new accounts and unknown-email prelogin responses use.
// Argon2id parameters follow Bitwarden's defaults (m=64MiB, t=3, p=4), which
// meet/exceed OWASP guidance.
var DefaultKDF = storage.KDFParams{
	Type:        "argon2id",
	Iterations:  3,
	MemoryMiB:   64,
	Parallelism: 4,
}

// TODO(Phase 2): HashVerifier(masterPasswordHash) using golang.org/x/crypto/argon2
// and VerifyVerifier(stored, provided); IssueTokens / refresh with JWT.
