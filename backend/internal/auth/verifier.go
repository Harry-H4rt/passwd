package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// The verifier is Argon2id over the client's master-password-hash (already a
// 256-bit value), so it's defense-in-depth against a DB leak rather than the
// primary work factor. Moderate params keep login fast while staying at/above
// OWASP minimums.
type verifierParams struct {
	timeCost uint32
	memKiB   uint32
	threads  uint8
}

var defaultVerifier = verifierParams{timeCost: 2, memKiB: 19 * 1024, threads: 1}

var phcB64 = base64.RawStdEncoding

// HashVerifier produces a PHC-encoded Argon2id hash with a random salt.
func HashVerifier(masterPasswordHash string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	p := defaultVerifier
	h := argon2.IDKey([]byte(masterPasswordHash), salt, p.timeCost, p.memKiB, p.threads, 32)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.memKiB, p.timeCost, p.threads,
		phcB64.EncodeToString(salt), phcB64.EncodeToString(h)), nil
}

// decoyVerifier is a real Argon2id verifier over a random value, computed once.
// Verifying a candidate against it costs the same as a genuine verification.
var (
	decoyOnce     sync.Once
	decoyVerifier string
)

func decoy() string {
	decoyOnce.Do(func() {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return
		}
		if v, err := HashVerifier(base64.RawStdEncoding.EncodeToString(b)); err == nil {
			decoyVerifier = v
		}
	})
	return decoyVerifier
}

// DummyVerify performs the same Argon2id work as VerifyVerifier against a decoy
// verifier, so a request for an unknown account is indistinguishable by timing
// from a wrong password for an existing one. This closes the account-enumeration
// side channel. It intentionally returns nothing; the caller still denies access.
func DummyVerify(masterPasswordHash string) {
	if d := decoy(); d != "" {
		_, _ = VerifyVerifier(d, masterPasswordHash)
	}
}

// VerifyVerifier reports whether masterPasswordHash matches the stored verifier,
// using a constant-time comparison.
func VerifyVerifier(encoded, masterPasswordHash string) (bool, error) {
	p, salt, hash, err := decodePHC(encoded)
	if err != nil {
		return false, err
	}
	computed := argon2.IDKey([]byte(masterPasswordHash), salt, p.timeCost, p.memKiB, p.threads, uint32(len(hash)))
	return subtle.ConstantTimeCompare(computed, hash) == 1, nil
}

func decodePHC(s string) (verifierParams, []byte, []byte, error) {
	// $argon2id$v=19$m=..,t=..,p=..$<salt>$<hash>
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return verifierParams{}, nil, nil, errors.New("auth: malformed verifier")
	}
	var version, mem, t, p int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return verifierParams{}, nil, nil, err
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &t, &p); err != nil {
		return verifierParams{}, nil, nil, err
	}
	salt, err := phcB64.DecodeString(parts[4])
	if err != nil {
		return verifierParams{}, nil, nil, err
	}
	hash, err := phcB64.DecodeString(parts[5])
	if err != nil {
		return verifierParams{}, nil, nil, err
	}
	return verifierParams{timeCost: uint32(t), memKiB: uint32(mem), threads: uint8(p)}, salt, hash, nil
}
