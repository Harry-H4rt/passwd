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
	// PublicKey is the user's sharing public key (base64 SPKI), uploaded at
	// registration so others can encrypt shared items to them. ProtectedPrivateKey
	// is the matching private key wrapped by the User Key; the server can't read it.
	PublicKey           string
	ProtectedPrivateKey string
	// RecoveryProtectedUserKey is the same User Key independently wrapped by a key
	// derived from the user's recovery code (EncString). Empty until the user opts
	// in. Lets a user who forgot the master password recover without a server reset.
	RecoveryProtectedUserKey string
	// RecoveryVerifier = Argon2id(recoveryAuthHash, randomSalt), PHC-encoded — the
	// server-side proof-of-possession for the recovery code. Empty until enrolled.
	// Like the master-password verifier, the server never sees the code itself.
	RecoveryVerifier string
	// TOTPSecret is a server-held second-factor secret (base32). 2FA requires the
	// server to verify codes, so unlike vault data this is not zero-knowledge — it
	// is an auth factor, never vault content. Empty until enrolled.
	TOTPSecret  string
	TOTPEnabled bool
	// TOTPLastCounter is the most recent TOTP time-step consumed at login. Codes
	// with a step counter <= this are rejected, so a code cannot be replayed within
	// its validity window. Reset whenever the secret changes.
	TOTPLastCounter uint64
	CreatedAt       time.Time
	UpdatedAt       time.Time
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

// WebAuthnCredential is an enrolled passkey used as a second factor. Like the TOTP
// secret it is an auth factor (the server must verify assertions against it), never
// vault content. A passkey stores only a public key, so a DB leak cannot be used to
// authenticate. The plaintext identifier never appears here — credentials are owned
// by the random UserID.
type WebAuthnCredential struct {
	ID              string // our row id
	UserID          string
	CredentialID    []byte // the authenticator's credential ID (unique per passkey)
	PublicKey       []byte // COSE public key
	AttestationType string
	Transports      string // JSON array of transport hints ("usb","internal",...)
	AAGUID          []byte // authenticator model id
	SignCount       uint32 // last seen signature counter (clone detection)
	Name            string // user-facing label, e.g. "YubiKey 5"
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// AuditEvent is one entry in the append-only security log. To preserve the
// zero-knowledge/no-PII stance it records the internal random account id and an
// event type only — never the plaintext identifier, and (by default) no IP. Detail
// is a short, non-PII qualifier such as "method=totp".
type AuditEvent struct {
	ID        string
	UserID    string // random account id; empty when not attributable to an account
	Event     string // e.g. "login.success", "login.failure", "cipher.create"
	Detail    string // optional, non-PII
	CreatedAt time.Time
}

// Share is one item shared from one user to another. The payload is opaque to the
// server: WrappedKey is the item key encrypted to the recipient's public key, and
// Data is the item ciphertext under that key.
type Share struct {
	ID              string
	OwnerUserID     string
	RecipientUserID string
	WrappedKey      string
	Data            string
	CreatedAt       time.Time
}

// RefreshToken is a persisted, rotatable session credential. Only a hash of the
// opaque token is stored, so a DB leak cannot be used to mint sessions.
type RefreshToken struct {
	TokenHash string // SHA-256 of the opaque token
	UserID    string
	ExpiresAt time.Time
	CreatedAt time.Time
	// Used marks a token that has already been rotated. A used token is kept (not
	// deleted) so that presenting it again is detected as token reuse/theft.
	Used bool
}

// Store is the persistence interface. Implementations must be safe for concurrent
// use.
type Store interface {
	CreateUser(ctx context.Context, u User) error
	GetUserByIdentifierHash(ctx context.Context, identifierHash string) (User, error)
	GetUserByID(ctx context.Context, id string) (User, error)
	SetUserTOTP(ctx context.Context, userID, secret string, enabled bool) error
	// SetUserTOTPCounter records the last TOTP time-step consumed at login (replay
	// protection).
	SetUserTOTPCounter(ctx context.Context, userID string, counter uint64) error

	// SetUserRecovery stores (or replaces) the recovery-wrapped User Key and the
	// recovery verifier. ClearUserRecovery removes both (recovery disabled).
	SetUserRecovery(ctx context.Context, userID, recoveryProtectedUserKey, recoveryVerifier string) error
	ClearUserRecovery(ctx context.Context, userID string) error
	// RotateMasterPassword swaps in a new master-password verifier, the re-wrapped
	// protected User Key, and KDF params. Used by the recovery flow (and a future
	// change-password flow). The recovery-wrapped key is untouched.
	RotateMasterPassword(ctx context.Context, userID, verifier, protectedUserKey string, kdf KDFParams) error
	// DeleteAccount permanently removes a user and every row attributable to them
	// (ciphers, refresh tokens, passkeys, audit events, and shares they own or
	// received), atomically. Returns ErrNotFound if the user does not exist.
	DeleteAccount(ctx context.Context, userID string) error

	CreateWebAuthnCredential(ctx context.Context, c WebAuthnCredential) error
	ListWebAuthnCredentials(ctx context.Context, userID string) ([]WebAuthnCredential, error)
	CountWebAuthnCredentials(ctx context.Context, userID string) (int, error)
	UpdateWebAuthnSignCount(ctx context.Context, credentialID []byte, signCount uint32) error
	DeleteWebAuthnCredential(ctx context.Context, userID, id string) error

	CreateCipher(ctx context.Context, c Cipher) error
	UpdateCipher(ctx context.Context, c Cipher) error
	DeleteCipher(ctx context.Context, userID, id string) error
	ListCiphers(ctx context.Context, userID string) ([]Cipher, error)

	CreateRefreshToken(ctx context.Context, rt RefreshToken) error
	GetRefreshToken(ctx context.Context, tokenHash string) (RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, tokenHash string) error
	// MarkRefreshTokenUsed flags a token as rotated without deleting it, so a later
	// presentation of the same token can be detected as reuse.
	MarkRefreshTokenUsed(ctx context.Context, tokenHash string) error
	// DeleteRefreshTokensForUser revokes every refresh token for a user. Used on
	// detected token reuse and on master-password rotation (recovery).
	DeleteRefreshTokensForUser(ctx context.Context, userID string) error

	// AppendAuditEvent records one entry in the append-only security log.
	AppendAuditEvent(ctx context.Context, e AuditEvent) error
	// ListAuditEvents returns a user's events, newest first, capped at limit.
	ListAuditEvents(ctx context.Context, userID string, limit int) ([]AuditEvent, error)

	// CreateShare stores a shared item. ListSharesForRecipient returns shares
	// addressed to a user (newest first). DeleteShare removes a share if the caller
	// is its owner or recipient.
	CreateShare(ctx context.Context, s Share) error
	ListSharesForRecipient(ctx context.Context, recipientUserID string) ([]Share, error)
	DeleteShare(ctx context.Context, userID, id string) error

	Close() error
}
