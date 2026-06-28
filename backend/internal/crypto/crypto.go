// Package crypto is a Go reference implementation of the @passwd/crypto key
// hierarchy (docs/CRYPTO.md). It mirrors the TypeScript client byte-for-byte and
// is validated against the shared docs/test-vectors.json, guaranteeing the client
// and server never disagree on the crypto. The zero-knowledge server does not
// derive user keys at runtime — this exists for verification and any future
// server-side crypto needs.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"regexp"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// KDFParams mirrors the TS KdfParams / storage.KDFParams shape.
type KDFParams struct {
	Type        string // "argon2id" | "pbkdf2"
	Iterations  int
	MemoryMiB   int
	Parallelism int
}

var wsRun = regexp.MustCompile(`\s+`)

// NormalizeIdentifier matches the TS normalizeIdentifier: trim, lowercase, and
// collapse internal whitespace runs to a single space.
//
// Note: the client also applies Unicode NFKC to the *password* before derivation;
// that is a client responsibility (the server never sees the password). For the
// ASCII test vectors NFKC is a no-op.
func NormalizeIdentifier(identifier string) string {
	return wsRun.ReplaceAllString(strings.ToLower(strings.TrimSpace(identifier)), " ")
}

// DeriveMasterKey = KDF(password, salt = normalize(identifier)) -> 32 bytes.
func DeriveMasterKey(password, identifier string, p KDFParams) ([]byte, error) {
	salt := []byte(NormalizeIdentifier(identifier))
	return DeriveKey([]byte(password), salt, p)
}

// DeriveKey runs the configured KDF over raw password/salt bytes.
func DeriveKey(password, salt []byte, p KDFParams) ([]byte, error) {
	switch p.Type {
	case "pbkdf2":
		return pbkdf2.Key(password, salt, p.Iterations, 32, sha256.New), nil
	case "argon2id":
		mem := uint32(p.MemoryMiB) * 1024 // MiB -> KiB
		return argon2.IDKey(password, salt, uint32(p.Iterations), mem, uint8(p.Parallelism), 32), nil
	default:
		return nil, fmt.Errorf("crypto: unknown KDF type %q", p.Type)
	}
}

// HKDFExpand is RFC 5869 expand-only with the given pseudorandom key.
func HKDFExpand(prk []byte, info string, length int) ([]byte, error) {
	r := hkdf.Expand(sha256.New, prk, []byte(info))
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// DeriveMasterPasswordHash is the authentication credential: one PBKDF2 pass over
// the master key salted by the password, base64-encoded. Mirrors the TS function.
func DeriveMasterPasswordHash(masterKey []byte, password string) string {
	h := pbkdf2.Key(masterKey, []byte(password), 1, 32, sha256.New)
	return base64.StdEncoding.EncodeToString(h)
}

// AESGCMEncrypt returns ciphertext||tag, matching WebCrypto AES-GCM.
func AESGCMEncrypt(key, nonce, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, nil), nil
}

// SerializeEncString mirrors the TS EncString format "<type>.<b64(nonce)>|<b64(data)>".
func SerializeEncString(encType int, nonce, data []byte) string {
	b := base64.StdEncoding
	return fmt.Sprintf("%d.%s|%s", encType, b.EncodeToString(nonce), b.EncodeToString(data))
}
