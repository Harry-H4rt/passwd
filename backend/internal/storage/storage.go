// Package storage defines the persistence boundary. Everything stored here is
// either opaque ciphertext or the cryptographic minimum needed to authenticate —
// never plaintext secrets and never PII. The server holds no email, no item type,
// no hints. The Store interface lets us start single-tenant (SQLite) and swap in
// Postgres for SaaS without touching domain code. See docs/ARCHITECTURE.md.
package storage

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("storage: not found")
	ErrConflict = errors.New("storage: already exists")
)

// KDFParams describe how the client derived the master key, so it can reproduce
// the derivation at login. Not secret.
type KDFParams struct {
	Type        string `json:"type"`                  // "argon2id" | "pbkdf2"
	Iterations  int    `json:"iterations"`            // argon2 time cost OR pbkdf2 rounds
	MemoryMiB   int    `json:"memoryMiB,omitempty"`   // argon2 only
	Parallelism int    `json:"parallelism,omitempty"` // argon2 only
}

// User holds only what a zero-knowledge server is permitted to know. Note there is
// no email/identifier in plaintext — only its blinded HMAC.
type User struct {
	ID string
	// IdentifierHash = HMAC-SHA256(serverPepper, normalize(identifier)). The login
	// handle (passphrase or email) is never stored in the clear, so the server
	// cannot enumerate, read, or contact its users.
	IdentifierHash string
	KDF            KDFParams
	// MasterPasswordVerifier = Argon2id(masterPasswordHash, randomSalt), PHC-encoded.
	MasterPasswordVerifier string
	// ProtectedUserKey is the User Key wrapped by the stretched master key (EncString).
	ProtectedUserKey string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// Cipher is a fully opaque encrypted vault item. The server stores no item type —
// the kind of item (login/card/note) lives inside the encrypted Data and is never
// visible to the server.
type Cipher struct {
	ID        string
	UserID    string
	Data      string // EncString ciphertext
	CreatedAt time.Time
	UpdatedAt time.Time
}

// RefreshToken is a persisted, rotatable session credential. Only a hash of the
// opaque token is stored, so a DB leak cannot be used to mint sessions.
type RefreshToken struct {
	TokenHash string // SHA-256 of the opaque token
	UserID    string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// Store is the persistence interface. Implementations must be safe for concurrent
// use.
type Store interface {
	CreateUser(ctx context.Context, u User) error
	GetUserByIdentifierHash(ctx context.Context, identifierHash string) (User, error)
	GetUserByID(ctx context.Context, id string) (User, error)

	CreateCipher(ctx context.Context, c Cipher) error
	UpdateCipher(ctx context.Context, c Cipher) error
	DeleteCipher(ctx context.Context, userID, id string) error
	ListCiphers(ctx context.Context, userID string) ([]Cipher, error)

	CreateRefreshToken(ctx context.Context, rt RefreshToken) error
	GetRefreshToken(ctx context.Context, tokenHash string) (RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, tokenHash string) error

	Close() error
}
