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
	created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id);
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
			kdf_parallelism, verifier, protected_user_key, created_at, updated_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?)`,
		u.ID, u.IdentifierHash, u.KDF.Type, u.KDF.Iterations, u.KDF.MemoryMiB,
		u.KDF.Parallelism, u.MasterPasswordVerifier, u.ProtectedUserKey, unix(u.CreatedAt), unix(u.UpdatedAt))
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

func (s *SQLite) scanUser(row *sql.Row) (User, error) {
	var u User
	var created, updated int64
	err := row.Scan(&u.ID, &u.IdentifierHash, &u.KDF.Type, &u.KDF.Iterations,
		&u.KDF.MemoryMiB, &u.KDF.Parallelism, &u.MasterPasswordVerifier,
		&u.ProtectedUserKey, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	u.CreatedAt, u.UpdatedAt = fromUnix(created), fromUnix(updated)
	return u, nil
}

const userCols = `id, identifier_hash, kdf_type, kdf_iterations, kdf_memory_mib,
	kdf_parallelism, verifier, protected_user_key, created_at, updated_at`

func (s *SQLite) GetUserByIdentifierHash(ctx context.Context, identifierHash string) (User, error) {
	return s.scanUser(s.db.QueryRowContext(ctx,
		`SELECT `+userCols+` FROM users WHERE identifier_hash = ?`, identifierHash))
}

func (s *SQLite) GetUserByID(ctx context.Context, id string) (User, error) {
	return s.scanUser(s.db.QueryRowContext(ctx,
		`SELECT `+userCols+` FROM users WHERE id = ?`, id))
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
	err := s.db.QueryRowContext(ctx,
		`SELECT token_hash, user_id, expires_at, created_at FROM refresh_tokens WHERE token_hash = ?`, tokenHash).
		Scan(&rt.TokenHash, &rt.UserID, &expires, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return RefreshToken{}, ErrNotFound
	}
	if err != nil {
		return RefreshToken{}, err
	}
	rt.ExpiresAt, rt.CreatedAt = fromUnix(expires), fromUnix(created)
	return rt, nil
}

func (s *SQLite) DeleteRefreshToken(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE token_hash = ?`, tokenHash)
	return err
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
