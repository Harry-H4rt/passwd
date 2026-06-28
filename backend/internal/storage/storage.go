// Package storage defines the persistence boundary. Everything stored here is
// either opaque ciphertext or non-secret metadata — the zero-knowledge server
// never holds anything it could use to decrypt a vault. The Store interface lets
// us start in-memory/SQLite (single-tenant) and swap in Postgres for SaaS
// without touching domain code. See docs/ARCHITECTURE.md.
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

// KDFParams describe how the client derived the master key. Stored so the client
// can reproduce the derivation at login time. Not secret.
type KDFParams struct {
	Type        string `json:"type"`                  // "argon2id" | "pbkdf2"
	Iterations  int    `json:"iterations"`            // argon2 time cost OR pbkdf2 rounds
	MemoryMiB   int    `json:"memoryMiB,omitempty"`   // argon2 only
	Parallelism int    `json:"parallelism,omitempty"` // argon2 only
}

// User holds only what a zero-knowledge server is permitted to know.
type User struct {
	ID    string
	Email string
	KDF   KDFParams
	// MasterPasswordVerifier = serverHash(masterPasswordHash, randomSalt).
	// Phase 2 makes serverHash = Argon2id; never store the client value directly.
	MasterPasswordVerifier string
	// ProtectedUserKey is the User Key wrapped by the stretched master key,
	// serialized as an EncString. The server cannot unwrap it.
	ProtectedUserKey string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// Cipher is an opaque encrypted vault item. Data is an EncString the server
// never decrypts; Type is a client-defined category kept in the clear for
// list/filter UX (it leaks only the *kind* of item, not its contents).
type Cipher struct {
	ID        string
	UserID    string
	Type      int
	Data      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Store is the persistence interface. Implementations must be safe for
// concurrent use.
type Store interface {
	CreateUser(ctx context.Context, u User) error
	GetUserByEmail(ctx context.Context, email string) (User, error)
	GetUserByID(ctx context.Context, id string) (User, error)

	CreateCipher(ctx context.Context, c Cipher) error
	UpdateCipher(ctx context.Context, c Cipher) error
	DeleteCipher(ctx context.Context, userID, id string) error
	ListCiphers(ctx context.Context, userID string) ([]Cipher, error)
}
