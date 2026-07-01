package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver, no cgo -> single static binary
)

// SQLite is a durable single-tenant Store. The same schema is intentionally close
// to what a Postgres SaaS impl would use (user_id on every row), so the SaaS path
// is a new implementation of this interface, not a redesign.
type SQLite struct {
	db *sql.DB
}

const sqliteSchema = `
CREATE TABLE IF NOT EXISTS users (
	id                 TEXT PRIMARY KEY,
	identifier_hash    TEXT NOT NULL UNIQUE,
	kdf_type           TEXT NOT NULL,
	kdf_iterations     INTEGER NOT NULL,
	kdf_memory_mib     INTEGER NOT NULL,
	kdf_parallelism    INTEGER NOT NULL,
	verifier           TEXT NOT NULL,
	protected_user_key TEXT NOT NULL,
	totp_secret        TEXT NOT NULL DEFAULT '',
	totp_enabled       INTEGER NOT NULL DEFAULT 0,
	totp_last_counter  INTEGER NOT NULL DEFAULT 0,
	recovery_protected_user_key TEXT NOT NULL DEFAULT '',
	recovery_verifier  TEXT NOT NULL DEFAULT '',
	public_key         TEXT NOT NULL DEFAULT '',
	protected_private_key TEXT NOT NULL DEFAULT '',
	created_at         INTEGER NOT NULL,
	updated_at         INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS ciphers (
	id         TEXT PRIMARY KEY,
	user_id    TEXT NOT NULL,
	data       TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ciphers_user ON ciphers(user_id);
CREATE TABLE IF NOT EXISTS refresh_tokens (
	token_hash TEXT PRIMARY KEY,
	user_id    TEXT NOT NULL,
	expires_at INTEGER NOT NULL,
	created_at INTEGER NOT NULL,
	used       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id);
CREATE TABLE IF NOT EXISTS webauthn_credentials (
	id               TEXT PRIMARY KEY,
	user_id          TEXT NOT NULL,
	credential_id    BLOB NOT NULL UNIQUE,
	public_key       BLOB NOT NULL,
	attestation_type TEXT NOT NULL DEFAULT '',
	transports       TEXT NOT NULL DEFAULT '',
	aaguid           BLOB,
	sign_count       INTEGER NOT NULL DEFAULT 0,
	name             TEXT NOT NULL DEFAULT '',
	created_at       INTEGER NOT NULL,
	updated_at       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_credentials(user_id);
CREATE TABLE IF NOT EXISTS audit_events (
	id         TEXT PRIMARY KEY,
	user_id    TEXT NOT NULL DEFAULT '',
	event      TEXT NOT NULL,
	detail     TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_events(user_id, created_at);
CREATE TABLE IF NOT EXISTS shares (
	id                TEXT PRIMARY KEY,
	owner_user_id     TEXT NOT NULL,
	recipient_user_id TEXT NOT NULL,
	wrapped_key       TEXT NOT NULL,
	data              TEXT NOT NULL,
	created_at        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_shares_recipient ON shares(recipient_user_id);
`

// OpenSQLite opens (and migrates) the database at path. Pragmas enable WAL and a
// busy timeout for safer concurrent access.
func OpenSQLite(path string) (*SQLite, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.ExecContext(context.Background(), sqliteSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	// Idempotent column additions for databases created before these columns
	// existed. SQLite has no ADD COLUMN IF NOT EXISTS, so ignore "duplicate
	// column" errors.
	for _, stmt := range []string{
		`ALTER TABLE users ADD COLUMN totp_secret TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN recovery_protected_user_key TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE users ADD COLUMN recovery_verifier TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE users ADD COLUMN totp_last_counter INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE refresh_tokens ADD COLUMN used INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN public_key TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE users ADD COLUMN protected_private_key TEXT NOT NULL DEFAULT ''`,
	} {
		if _, err := db.ExecContext(context.Background(), stmt); err != nil &&
			!strings.Contains(err.Error(), "duplicate column name") {
			_ = db.Close()
			return nil, fmt.Errorf("migrate: %w", err)
		}
	}
	return &SQLite{db: db}, nil
}

var _ Store = (*SQLite)(nil)

func (s *SQLite) Close() error { return s.db.Close() }

func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func unix(t time.Time) int64     { return t.UTC().Unix() }
func fromUnix(n int64) time.Time { return time.Unix(n, 0).UTC() }

func (s *SQLite) CreateUser(ctx context.Context, u User) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (id, identifier_hash, kdf_type, kdf_iterations, kdf_memory_mib,
			kdf_parallelism, verifier, protected_user_key, totp_secret, totp_enabled,
			recovery_protected_user_key, recovery_verifier, public_key, protected_private_key,
			created_at, updated_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		u.ID, u.IdentifierHash, u.KDF.Type, u.KDF.Iterations, u.KDF.MemoryMiB,
		u.KDF.Parallelism, u.MasterPasswordVerifier, u.ProtectedUserKey,
		u.TOTPSecret, boolToInt(u.TOTPEnabled),
		u.RecoveryProtectedUserKey, u.RecoveryVerifier, u.PublicKey, u.ProtectedPrivateKey,
		unix(u.CreatedAt), unix(u.UpdatedAt))
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

func (s *SQLite) scanUser(row *sql.Row) (User, error) {
	var u User
	var created, updated int64
	var totpEnabled int
	err := row.Scan(&u.ID, &u.IdentifierHash, &u.KDF.Type, &u.KDF.Iterations,
		&u.KDF.MemoryMiB, &u.KDF.Parallelism, &u.MasterPasswordVerifier,
		&u.ProtectedUserKey, &u.TOTPSecret, &totpEnabled, &u.TOTPLastCounter,
		&u.RecoveryProtectedUserKey, &u.RecoveryVerifier, &u.PublicKey, &u.ProtectedPrivateKey,
		&created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	u.TOTPEnabled = totpEnabled != 0
	u.CreatedAt, u.UpdatedAt = fromUnix(created), fromUnix(updated)
	return u, nil
}

const userCols = `id, identifier_hash, kdf_type, kdf_iterations, kdf_memory_mib,
	kdf_parallelism, verifier, protected_user_key, totp_secret, totp_enabled,
	totp_last_counter, recovery_protected_user_key, recovery_verifier,
	public_key, protected_private_key, created_at, updated_at`

func (s *SQLite) GetUserByIdentifierHash(ctx context.Context, identifierHash string) (User, error) {
	return s.scanUser(s.db.QueryRowContext(ctx,
		`SELECT `+userCols+` FROM users WHERE identifier_hash = ?`, identifierHash))
}

func (s *SQLite) GetUserByID(ctx context.Context, id string) (User, error) {
	return s.scanUser(s.db.QueryRowContext(ctx,
		`SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

func (s *SQLite) SetUserTOTP(ctx context.Context, userID, secret string, enabled bool) error {
	// Reset the replay baseline whenever the secret changes.
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET totp_secret = ?, totp_enabled = ?, totp_last_counter = 0 WHERE id = ?`,
		secret, boolToInt(enabled), userID)
	if err != nil {
		return err
	}
	return notFoundIfNoRows(res)
}

func (s *SQLite) SetUserTOTPCounter(ctx context.Context, userID string, counter uint64) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET totp_last_counter = ? WHERE id = ?`, counter, userID)
	if err != nil {
		return err
	}
	return notFoundIfNoRows(res)
}

func (s *SQLite) SetUserRecovery(ctx context.Context, userID, recoveryProtectedUserKey, recoveryVerifier string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET recovery_protected_user_key = ?, recovery_verifier = ?, updated_at = ? WHERE id = ?`,
		recoveryProtectedUserKey, recoveryVerifier, unix(time.Now()), userID)
	if err != nil {
		return err
	}
	return notFoundIfNoRows(res)
}

func (s *SQLite) ClearUserRecovery(ctx context.Context, userID string) error {
	return s.SetUserRecovery(ctx, userID, "", "")
}

func (s *SQLite) RotateMasterPassword(ctx context.Context, userID, verifier, protectedUserKey string, kdf KDFParams) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET verifier = ?, protected_user_key = ?,
			kdf_type = ?, kdf_iterations = ?, kdf_memory_mib = ?, kdf_parallelism = ?, updated_at = ?
		 WHERE id = ?`,
		verifier, protectedUserKey, kdf.Type, kdf.Iterations, kdf.MemoryMiB, kdf.Parallelism,
		unix(time.Now()), userID)
	if err != nil {
		return err
	}
	return notFoundIfNoRows(res)
}

// DeleteAccount removes the user and all of their data in one transaction, so a
// failure part-way leaves the account intact rather than half-deleted.
func (s *SQLite) DeleteAccount(ctx context.Context, userID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	for _, q := range []string{
		`DELETE FROM ciphers WHERE user_id = ?`,
		`DELETE FROM refresh_tokens WHERE user_id = ?`,
		`DELETE FROM webauthn_credentials WHERE user_id = ?`,
		`DELETE FROM audit_events WHERE user_id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, q, userID); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM shares WHERE owner_user_id = ? OR recipient_user_id = ?`, userID, userID); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, userID)
	if err != nil {
		return err
	}
	if err := notFoundIfNoRows(res); err != nil {
		return err
	}
	return tx.Commit()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *SQLite) CreateWebAuthnCredential(ctx context.Context, c WebAuthnCredential) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO webauthn_credentials
			(id, user_id, credential_id, public_key, attestation_type, transports, aaguid, sign_count, name, created_at, updated_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		c.ID, c.UserID, c.CredentialID, c.PublicKey, c.AttestationType, c.Transports,
		c.AAGUID, c.SignCount, c.Name, unix(c.CreatedAt), unix(c.UpdatedAt))
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

func (s *SQLite) ListWebAuthnCredentials(ctx context.Context, userID string) ([]WebAuthnCredential, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, credential_id, public_key, attestation_type, transports, aaguid, sign_count, name, created_at, updated_at
		 FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]WebAuthnCredential, 0)
	for rows.Next() {
		var c WebAuthnCredential
		var created, updated int64
		if err := rows.Scan(&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey, &c.AttestationType,
			&c.Transports, &c.AAGUID, &c.SignCount, &c.Name, &created, &updated); err != nil {
			return nil, err
		}
		c.CreatedAt, c.UpdatedAt = fromUnix(created), fromUnix(updated)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *SQLite) CountWebAuthnCredentials(ctx context.Context, userID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?`, userID).Scan(&n)
	return n, err
}

func (s *SQLite) UpdateWebAuthnSignCount(ctx context.Context, credentialID []byte, signCount uint32) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE webauthn_credentials SET sign_count = ?, updated_at = ? WHERE credential_id = ?`,
		signCount, unix(time.Now()), credentialID)
	if err != nil {
		return err
	}
	return notFoundIfNoRows(res)
}

func (s *SQLite) DeleteWebAuthnCredential(ctx context.Context, userID, id string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return err
	}
	return notFoundIfNoRows(res)
}

func (s *SQLite) CreateCipher(ctx context.Context, c Cipher) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO ciphers (id, user_id, data, created_at, updated_at) VALUES (?,?,?,?,?)`,
		c.ID, c.UserID, c.Data, unix(c.CreatedAt), unix(c.UpdatedAt))
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

func (s *SQLite) UpdateCipher(ctx context.Context, c Cipher) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE ciphers SET data = ?, updated_at = ? WHERE id = ? AND user_id = ?`,
		c.Data, unix(c.UpdatedAt), c.ID, c.UserID)
	if err != nil {
		return err
	}
	return notFoundIfNoRows(res)
}

func (s *SQLite) DeleteCipher(ctx context.Context, userID, id string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM ciphers WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return err
	}
	return notFoundIfNoRows(res)
}

func (s *SQLite) ListCiphers(ctx context.Context, userID string) ([]Cipher, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, data, created_at, updated_at FROM ciphers WHERE user_id = ? ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Cipher, 0)
	for rows.Next() {
		var c Cipher
		var created, updated int64
		if err := rows.Scan(&c.ID, &c.UserID, &c.Data, &created, &updated); err != nil {
			return nil, err
		}
		c.CreatedAt, c.UpdatedAt = fromUnix(created), fromUnix(updated)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *SQLite) CreateRefreshToken(ctx context.Context, rt RefreshToken) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO refresh_tokens (token_hash, user_id, expires_at, created_at) VALUES (?,?,?,?)`,
		rt.TokenHash, rt.UserID, unix(rt.ExpiresAt), unix(rt.CreatedAt))
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

func (s *SQLite) GetRefreshToken(ctx context.Context, tokenHash string) (RefreshToken, error) {
	var rt RefreshToken
	var expires, created int64
	var used int
	err := s.db.QueryRowContext(ctx,
		`SELECT token_hash, user_id, expires_at, created_at, used FROM refresh_tokens WHERE token_hash = ?`, tokenHash).
		Scan(&rt.TokenHash, &rt.UserID, &expires, &created, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return RefreshToken{}, ErrNotFound
	}
	if err != nil {
		return RefreshToken{}, err
	}
	rt.ExpiresAt, rt.CreatedAt = fromUnix(expires), fromUnix(created)
	rt.Used = used != 0
	return rt, nil
}

func (s *SQLite) DeleteRefreshToken(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE token_hash = ?`, tokenHash)
	return err
}

func (s *SQLite) MarkRefreshTokenUsed(ctx context.Context, tokenHash string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE refresh_tokens SET used = 1 WHERE token_hash = ?`, tokenHash)
	if err != nil {
		return err
	}
	return notFoundIfNoRows(res)
}

func (s *SQLite) DeleteRefreshTokensForUser(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE user_id = ?`, userID)
	return err
}

func (s *SQLite) ListRefreshTokensForUser(ctx context.Context, userID string) ([]RefreshToken, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT token_hash, user_id, expires_at, created_at, used FROM refresh_tokens
		 WHERE user_id = ? AND used = 0 AND expires_at > ? ORDER BY created_at DESC`, userID, unix(time.Now()))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]RefreshToken, 0)
	for rows.Next() {
		var rt RefreshToken
		var expires, created int64
		var used int
		if err := rows.Scan(&rt.TokenHash, &rt.UserID, &expires, &created, &used); err != nil {
			return nil, err
		}
		rt.ExpiresAt, rt.CreatedAt, rt.Used = fromUnix(expires), fromUnix(created), used != 0
		out = append(out, rt)
	}
	return out, rows.Err()
}

func (s *SQLite) AppendAuditEvent(ctx context.Context, e AuditEvent) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_events (id, user_id, event, detail, created_at) VALUES (?,?,?,?,?)`,
		e.ID, e.UserID, e.Event, e.Detail, unix(e.CreatedAt))
	return err
}

func (s *SQLite) ListAuditEvents(ctx context.Context, userID string, limit int) ([]AuditEvent, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, event, detail, created_at FROM audit_events
		 WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT ?`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AuditEvent, 0)
	for rows.Next() {
		var e AuditEvent
		var created int64
		if err := rows.Scan(&e.ID, &e.UserID, &e.Event, &e.Detail, &created); err != nil {
			return nil, err
		}
		e.CreatedAt = fromUnix(created)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *SQLite) CreateShare(ctx context.Context, sh Share) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO shares (id, owner_user_id, recipient_user_id, wrapped_key, data, created_at)
		 VALUES (?,?,?,?,?,?)`,
		sh.ID, sh.OwnerUserID, sh.RecipientUserID, sh.WrappedKey, sh.Data, unix(sh.CreatedAt))
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

func (s *SQLite) ListSharesForRecipient(ctx context.Context, recipientUserID string) ([]Share, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, owner_user_id, recipient_user_id, wrapped_key, data, created_at
		 FROM shares WHERE recipient_user_id = ? ORDER BY created_at DESC, id DESC`, recipientUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Share, 0)
	for rows.Next() {
		var sh Share
		var created int64
		if err := rows.Scan(&sh.ID, &sh.OwnerUserID, &sh.RecipientUserID, &sh.WrappedKey, &sh.Data, &created); err != nil {
			return nil, err
		}
		sh.CreatedAt = fromUnix(created)
		out = append(out, sh)
	}
	return out, rows.Err()
}

func (s *SQLite) DeleteShare(ctx context.Context, userID, id string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM shares WHERE id = ? AND (recipient_user_id = ? OR owner_user_id = ?)`,
		id, userID, userID)
	if err != nil {
		return err
	}
	return notFoundIfNoRows(res)
}

func notFoundIfNoRows(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
