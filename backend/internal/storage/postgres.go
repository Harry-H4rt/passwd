package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"
)

// Postgres is a durable, multi-tenant-ready Store backed by PostgreSQL. It mirrors
// the SQLite implementation's behaviour (and shares its contract tests) so the
// single-tenant SQLite path and a SaaS Postgres path stay byte-for-byte compatible
// at the domain layer. Timestamps are stored as BIGINT unix seconds, matching
// SQLite, via the shared unix()/fromUnix() helpers.
type Postgres struct {
	db *sql.DB
}

const postgresSchema = `
CREATE TABLE IF NOT EXISTS users (
	id                          TEXT PRIMARY KEY,
	identifier_hash             TEXT NOT NULL UNIQUE,
	kdf_type                    TEXT NOT NULL,
	kdf_iterations              INTEGER NOT NULL,
	kdf_memory_mib              INTEGER NOT NULL,
	kdf_parallelism             INTEGER NOT NULL,
	verifier                    TEXT NOT NULL,
	protected_user_key          TEXT NOT NULL,
	totp_secret                 TEXT NOT NULL DEFAULT '',
	totp_enabled                BOOLEAN NOT NULL DEFAULT FALSE,
	totp_last_counter           BIGINT NOT NULL DEFAULT 0,
	recovery_protected_user_key TEXT NOT NULL DEFAULT '',
	recovery_verifier           TEXT NOT NULL DEFAULT '',
	created_at                  BIGINT NOT NULL,
	updated_at                  BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS ciphers (
	id         TEXT PRIMARY KEY,
	user_id    TEXT NOT NULL,
	data       TEXT NOT NULL,
	created_at BIGINT NOT NULL,
	updated_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ciphers_user ON ciphers(user_id);
CREATE TABLE IF NOT EXISTS refresh_tokens (
	token_hash TEXT PRIMARY KEY,
	user_id    TEXT NOT NULL,
	expires_at BIGINT NOT NULL,
	created_at BIGINT NOT NULL,
	used       BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id);
CREATE TABLE IF NOT EXISTS webauthn_credentials (
	id               TEXT PRIMARY KEY,
	user_id          TEXT NOT NULL,
	credential_id    BYTEA NOT NULL UNIQUE,
	public_key       BYTEA NOT NULL,
	attestation_type TEXT NOT NULL DEFAULT '',
	transports       TEXT NOT NULL DEFAULT '',
	aaguid           BYTEA,
	sign_count       BIGINT NOT NULL DEFAULT 0,
	name             TEXT NOT NULL DEFAULT '',
	created_at       BIGINT NOT NULL,
	updated_at       BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_credentials(user_id);
CREATE TABLE IF NOT EXISTS audit_events (
	id         TEXT PRIMARY KEY,
	user_id    TEXT NOT NULL DEFAULT '',
	event      TEXT NOT NULL,
	detail     TEXT NOT NULL DEFAULT '',
	created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_events(user_id, created_at);
`

// OpenPostgres opens (and migrates) the database at the given DSN, e.g.
// "postgres://user:pass@host:5432/passwd?sslmode=require".
func OpenPostgres(dsn string) (*Postgres, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connect: %w", err)
	}
	if _, err := db.ExecContext(context.Background(), postgresSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Postgres{db: db}, nil
}

var _ Store = (*Postgres)(nil)

func (p *Postgres) Close() error { return p.db.Close() }

// isPGUnique reports a unique-constraint violation (SQLSTATE 23505).
func isPGUnique(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "23505"
}

func (p *Postgres) CreateUser(ctx context.Context, u User) error {
	_, err := p.db.ExecContext(ctx,
		`INSERT INTO users (id, identifier_hash, kdf_type, kdf_iterations, kdf_memory_mib,
			kdf_parallelism, verifier, protected_user_key, totp_secret, totp_enabled,
			recovery_protected_user_key, recovery_verifier, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		u.ID, u.IdentifierHash, u.KDF.Type, u.KDF.Iterations, u.KDF.MemoryMiB,
		u.KDF.Parallelism, u.MasterPasswordVerifier, u.ProtectedUserKey,
		u.TOTPSecret, u.TOTPEnabled,
		u.RecoveryProtectedUserKey, u.RecoveryVerifier, unix(u.CreatedAt), unix(u.UpdatedAt))
	if isPGUnique(err) {
		return ErrConflict
	}
	return err
}

func (p *Postgres) scanUser(row *sql.Row) (User, error) {
	var u User
	var created, updated int64
	err := row.Scan(&u.ID, &u.IdentifierHash, &u.KDF.Type, &u.KDF.Iterations,
		&u.KDF.MemoryMiB, &u.KDF.Parallelism, &u.MasterPasswordVerifier,
		&u.ProtectedUserKey, &u.TOTPSecret, &u.TOTPEnabled, &u.TOTPLastCounter,
		&u.RecoveryProtectedUserKey, &u.RecoveryVerifier, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	u.CreatedAt, u.UpdatedAt = fromUnix(created), fromUnix(updated)
	return u, nil
}

const pgUserCols = `id, identifier_hash, kdf_type, kdf_iterations, kdf_memory_mib,
	kdf_parallelism, verifier, protected_user_key, totp_secret, totp_enabled,
	totp_last_counter, recovery_protected_user_key, recovery_verifier,
	created_at, updated_at`

func (p *Postgres) GetUserByIdentifierHash(ctx context.Context, identifierHash string) (User, error) {
	return p.scanUser(p.db.QueryRowContext(ctx,
		`SELECT `+pgUserCols+` FROM users WHERE identifier_hash = $1`, identifierHash))
}

func (p *Postgres) GetUserByID(ctx context.Context, id string) (User, error) {
	return p.scanUser(p.db.QueryRowContext(ctx,
		`SELECT `+pgUserCols+` FROM users WHERE id = $1`, id))
}

func (p *Postgres) SetUserTOTP(ctx context.Context, userID, secret string, enabled bool) error {
	res, err := p.db.ExecContext(ctx,
		`UPDATE users SET totp_secret = $1, totp_enabled = $2, totp_last_counter = 0 WHERE id = $3`,
		secret, enabled, userID)
	if err != nil {
		return err
	}
	return notFoundIfNoRows(res)
}

func (p *Postgres) SetUserTOTPCounter(ctx context.Context, userID string, counter uint64) error {
	res, err := p.db.ExecContext(ctx,
		`UPDATE users SET totp_last_counter = $1 WHERE id = $2`, int64(counter), userID)
	if err != nil {
		return err
	}
	return notFoundIfNoRows(res)
}

func (p *Postgres) SetUserRecovery(ctx context.Context, userID, recoveryProtectedUserKey, recoveryVerifier string) error {
	res, err := p.db.ExecContext(ctx,
		`UPDATE users SET recovery_protected_user_key = $1, recovery_verifier = $2, updated_at = $3 WHERE id = $4`,
		recoveryProtectedUserKey, recoveryVerifier, unix(time.Now()), userID)
	if err != nil {
		return err
	}
	return notFoundIfNoRows(res)
}

func (p *Postgres) ClearUserRecovery(ctx context.Context, userID string) error {
	return p.SetUserRecovery(ctx, userID, "", "")
}

func (p *Postgres) RotateMasterPassword(ctx context.Context, userID, verifier, protectedUserKey string, kdf KDFParams) error {
	res, err := p.db.ExecContext(ctx,
		`UPDATE users SET verifier = $1, protected_user_key = $2,
			kdf_type = $3, kdf_iterations = $4, kdf_memory_mib = $5, kdf_parallelism = $6, updated_at = $7
		 WHERE id = $8`,
		verifier, protectedUserKey, kdf.Type, kdf.Iterations, kdf.MemoryMiB, kdf.Parallelism,
		unix(time.Now()), userID)
	if err != nil {
		return err
	}
	return notFoundIfNoRows(res)
}

func (p *Postgres) CreateWebAuthnCredential(ctx context.Context, c WebAuthnCredential) error {
	_, err := p.db.ExecContext(ctx,
		`INSERT INTO webauthn_credentials
			(id, user_id, credential_id, public_key, attestation_type, transports, aaguid, sign_count, name, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		c.ID, c.UserID, c.CredentialID, c.PublicKey, c.AttestationType, c.Transports,
		c.AAGUID, int64(c.SignCount), c.Name, unix(c.CreatedAt), unix(c.UpdatedAt))
	if isPGUnique(err) {
		return ErrConflict
	}
	return err
}

func (p *Postgres) ListWebAuthnCredentials(ctx context.Context, userID string) ([]WebAuthnCredential, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT id, user_id, credential_id, public_key, attestation_type, transports, aaguid, sign_count, name, created_at, updated_at
		 FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]WebAuthnCredential, 0)
	for rows.Next() {
		var c WebAuthnCredential
		var created, updated int64
		var signCount int64
		if err := rows.Scan(&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey, &c.AttestationType,
			&c.Transports, &c.AAGUID, &signCount, &c.Name, &created, &updated); err != nil {
			return nil, err
		}
		c.SignCount = uint32(signCount)
		c.CreatedAt, c.UpdatedAt = fromUnix(created), fromUnix(updated)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (p *Postgres) CountWebAuthnCredentials(ctx context.Context, userID string) (int, error) {
	var n int
	err := p.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = $1`, userID).Scan(&n)
	return n, err
}

func (p *Postgres) UpdateWebAuthnSignCount(ctx context.Context, credentialID []byte, signCount uint32) error {
	res, err := p.db.ExecContext(ctx,
		`UPDATE webauthn_credentials SET sign_count = $1, updated_at = $2 WHERE credential_id = $3`,
		int64(signCount), unix(time.Now()), credentialID)
	if err != nil {
		return err
	}
	return notFoundIfNoRows(res)
}

func (p *Postgres) DeleteWebAuthnCredential(ctx context.Context, userID, id string) error {
	res, err := p.db.ExecContext(ctx,
		`DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2`, id, userID)
	if err != nil {
		return err
	}
	return notFoundIfNoRows(res)
}

func (p *Postgres) CreateCipher(ctx context.Context, c Cipher) error {
	_, err := p.db.ExecContext(ctx,
		`INSERT INTO ciphers (id, user_id, data, created_at, updated_at) VALUES ($1,$2,$3,$4,$5)`,
		c.ID, c.UserID, c.Data, unix(c.CreatedAt), unix(c.UpdatedAt))
	if isPGUnique(err) {
		return ErrConflict
	}
	return err
}

func (p *Postgres) UpdateCipher(ctx context.Context, c Cipher) error {
	res, err := p.db.ExecContext(ctx,
		`UPDATE ciphers SET data = $1, updated_at = $2 WHERE id = $3 AND user_id = $4`,
		c.Data, unix(c.UpdatedAt), c.ID, c.UserID)
	if err != nil {
		return err
	}
	return notFoundIfNoRows(res)
}

func (p *Postgres) DeleteCipher(ctx context.Context, userID, id string) error {
	res, err := p.db.ExecContext(ctx,
		`DELETE FROM ciphers WHERE id = $1 AND user_id = $2`, id, userID)
	if err != nil {
		return err
	}
	return notFoundIfNoRows(res)
}

func (p *Postgres) ListCiphers(ctx context.Context, userID string) ([]Cipher, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT id, user_id, data, created_at, updated_at FROM ciphers WHERE user_id = $1 ORDER BY created_at`, userID)
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

func (p *Postgres) CreateRefreshToken(ctx context.Context, rt RefreshToken) error {
	_, err := p.db.ExecContext(ctx,
		`INSERT INTO refresh_tokens (token_hash, user_id, expires_at, created_at) VALUES ($1,$2,$3,$4)`,
		rt.TokenHash, rt.UserID, unix(rt.ExpiresAt), unix(rt.CreatedAt))
	if isPGUnique(err) {
		return ErrConflict
	}
	return err
}

func (p *Postgres) GetRefreshToken(ctx context.Context, tokenHash string) (RefreshToken, error) {
	var rt RefreshToken
	var expires, created int64
	err := p.db.QueryRowContext(ctx,
		`SELECT token_hash, user_id, expires_at, created_at, used FROM refresh_tokens WHERE token_hash = $1`, tokenHash).
		Scan(&rt.TokenHash, &rt.UserID, &expires, &created, &rt.Used)
	if errors.Is(err, sql.ErrNoRows) {
		return RefreshToken{}, ErrNotFound
	}
	if err != nil {
		return RefreshToken{}, err
	}
	rt.ExpiresAt, rt.CreatedAt = fromUnix(expires), fromUnix(created)
	return rt, nil
}

func (p *Postgres) DeleteRefreshToken(ctx context.Context, tokenHash string) error {
	_, err := p.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE token_hash = $1`, tokenHash)
	return err
}

func (p *Postgres) MarkRefreshTokenUsed(ctx context.Context, tokenHash string) error {
	res, err := p.db.ExecContext(ctx, `UPDATE refresh_tokens SET used = TRUE WHERE token_hash = $1`, tokenHash)
	if err != nil {
		return err
	}
	return notFoundIfNoRows(res)
}

func (p *Postgres) DeleteRefreshTokensForUser(ctx context.Context, userID string) error {
	_, err := p.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE user_id = $1`, userID)
	return err
}

func (p *Postgres) AppendAuditEvent(ctx context.Context, e AuditEvent) error {
	_, err := p.db.ExecContext(ctx,
		`INSERT INTO audit_events (id, user_id, event, detail, created_at) VALUES ($1,$2,$3,$4,$5)`,
		e.ID, e.UserID, e.Event, e.Detail, unix(e.CreatedAt))
	return err
}

func (p *Postgres) ListAuditEvents(ctx context.Context, userID string, limit int) ([]AuditEvent, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT id, user_id, event, detail, created_at FROM audit_events
		 WHERE user_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2`, userID, limit)
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
