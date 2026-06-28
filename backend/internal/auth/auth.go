// Package auth holds authentication policy: default KDF parameters, identifier
// blinding, the server-side password verifier (Argon2id), and token issuing.
//
// Zero-knowledge contract: the server receives the client's "master password
// hash" only as a login credential and stores Argon2id(it). It never sees the
// master password, the master key, or a plaintext identifier. See docs/CRYPTO.md.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"

	"github.com/passwd-app/server/internal/crypto"
	"github.com/passwd-app/server/internal/storage"
)

// DefaultKDF is what new accounts and unknown-identifier prelogin responses use.
// Mirrors the client's DEFAULT_KDF and meets OWASP guidance.
var DefaultKDF = storage.KDFParams{
	Type:        "argon2id",
	Iterations:  3,
	MemoryMiB:   64,
	Parallelism: 4,
}

// BlindIdentifier maps a login handle (passphrase or email) to the value stored
// and looked up server-side: HMAC-SHA256(pepper, normalize(identifier)). The
// pepper (a server secret) means a stolen database alone cannot confirm guessed
// identifiers, and the plaintext identifier is never persisted.
func BlindIdentifier(pepper, identifier string) string {
	mac := hmac.New(sha256.New, []byte(pepper))
	mac.Write([]byte(crypto.NormalizeIdentifier(identifier)))
	return hex.EncodeToString(mac.Sum(nil))
}
