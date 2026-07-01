package storage

import (
	"bytes"
	"context"
	"sort"
	"sync"
	"time"
)

// Memory is an in-memory Store for tests and ephemeral runs. Not durable.
type Memory struct {
	mu       sync.RWMutex
	users    map[string]User               // id -> User
	byIDHash map[string]string             // identifier hash -> user id
	ciphers  map[string]Cipher             // id -> Cipher
	refresh  map[string]RefreshToken       // token hash -> RefreshToken
	passkeys map[string]WebAuthnCredential // row id -> credential
	audit    []AuditEvent                  // append-only, oldest first
	shares   map[string]Share              // id -> Share
}

func NewMemory() *Memory {
	return &Memory{
		users:    make(map[string]User),
		byIDHash: make(map[string]string),
		ciphers:  make(map[string]Cipher),
		refresh:  make(map[string]RefreshToken),
		passkeys: make(map[string]WebAuthnCredential),
		shares:   make(map[string]Share),
	}
}

var _ Store = (*Memory)(nil)

func (m *Memory) CreateUser(_ context.Context, u User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.byIDHash[u.IdentifierHash]; exists {
		return ErrConflict
	}
	m.users[u.ID] = u
	m.byIDHash[u.IdentifierHash] = u.ID
	return nil
}

func (m *Memory) GetUserByIdentifierHash(_ context.Context, identifierHash string) (User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.byIDHash[identifierHash]
	if !ok {
		return User{}, ErrNotFound
	}
	return m.users[id], nil
}

func (m *Memory) GetUserByID(_ context.Context, id string) (User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[id]
	if !ok {
		return User{}, ErrNotFound
	}
	return u, nil
}

func (m *Memory) SetUserTOTP(_ context.Context, userID, secret string, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID]
	if !ok {
		return ErrNotFound
	}
	u.TOTPSecret = secret
	u.TOTPEnabled = enabled
	u.TOTPLastCounter = 0 // a new/cleared secret invalidates any old replay baseline
	m.users[userID] = u
	return nil
}

func (m *Memory) SetUserTOTPCounter(_ context.Context, userID string, counter uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID]
	if !ok {
		return ErrNotFound
	}
	u.TOTPLastCounter = counter
	m.users[userID] = u
	return nil
}

func (m *Memory) SetUserRecovery(_ context.Context, userID, recoveryProtectedUserKey, recoveryVerifier string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID]
	if !ok {
		return ErrNotFound
	}
	u.RecoveryProtectedUserKey = recoveryProtectedUserKey
	u.RecoveryVerifier = recoveryVerifier
	m.users[userID] = u
	return nil
}

func (m *Memory) ClearUserRecovery(_ context.Context, userID string) error {
	return m.SetUserRecovery(context.Background(), userID, "", "")
}

func (m *Memory) RotateMasterPassword(_ context.Context, userID, verifier, protectedUserKey string, kdf KDFParams) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID]
	if !ok {
		return ErrNotFound
	}
	u.MasterPasswordVerifier = verifier
	u.ProtectedUserKey = protectedUserKey
	u.KDF = kdf
	u.UpdatedAt = time.Now().UTC()
	m.users[userID] = u
	return nil
}

func (m *Memory) DeleteAccount(_ context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID]
	if !ok {
		return ErrNotFound
	}
	delete(m.users, userID)
	delete(m.byIDHash, u.IdentifierHash)
	for id, c := range m.ciphers {
		if c.UserID == userID {
			delete(m.ciphers, id)
		}
	}
	for h, rt := range m.refresh {
		if rt.UserID == userID {
			delete(m.refresh, h)
		}
	}
	for id, p := range m.passkeys {
		if p.UserID == userID {
			delete(m.passkeys, id)
		}
	}
	for id, sh := range m.shares {
		if sh.OwnerUserID == userID || sh.RecipientUserID == userID {
			delete(m.shares, id)
		}
	}
	kept := make([]AuditEvent, 0, len(m.audit))
	for _, e := range m.audit {
		if e.UserID != userID {
			kept = append(kept, e)
		}
	}
	m.audit = kept
	return nil
}

func (m *Memory) CreateWebAuthnCredential(_ context.Context, c WebAuthnCredential) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.passkeys {
		if bytes.Equal(existing.CredentialID, c.CredentialID) {
			return ErrConflict
		}
	}
	m.passkeys[c.ID] = c
	return nil
}

func (m *Memory) ListWebAuthnCredentials(_ context.Context, userID string) ([]WebAuthnCredential, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]WebAuthnCredential, 0)
	for _, c := range m.passkeys {
		if c.UserID == userID {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *Memory) CountWebAuthnCredentials(_ context.Context, userID string) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for _, c := range m.passkeys {
		if c.UserID == userID {
			n++
		}
	}
	return n, nil
}

func (m *Memory) UpdateWebAuthnSignCount(_ context.Context, credentialID []byte, signCount uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, c := range m.passkeys {
		if bytes.Equal(c.CredentialID, credentialID) {
			c.SignCount = signCount
			c.UpdatedAt = time.Now().UTC()
			m.passkeys[id] = c
			return nil
		}
	}
	return ErrNotFound
}

func (m *Memory) DeleteWebAuthnCredential(_ context.Context, userID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.passkeys[id]
	if !ok || c.UserID != userID {
		return ErrNotFound
	}
	delete(m.passkeys, id)
	return nil
}

func (m *Memory) CreateCipher(_ context.Context, c Cipher) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.ciphers[c.ID]; exists {
		return ErrConflict
	}
	m.ciphers[c.ID] = c
	return nil
}

func (m *Memory) UpdateCipher(_ context.Context, c Cipher) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.ciphers[c.ID]
	if !ok || existing.UserID != c.UserID {
		return ErrNotFound
	}
	m.ciphers[c.ID] = c
	return nil
}

func (m *Memory) DeleteCipher(_ context.Context, userID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.ciphers[id]
	if !ok || c.UserID != userID {
		return ErrNotFound
	}
	delete(m.ciphers, id)
	return nil
}

func (m *Memory) ListCiphers(_ context.Context, userID string) ([]Cipher, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Cipher, 0)
	for _, c := range m.ciphers {
		if c.UserID == userID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (m *Memory) CreateRefreshToken(_ context.Context, rt RefreshToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refresh[rt.TokenHash] = rt
	return nil
}

func (m *Memory) GetRefreshToken(_ context.Context, tokenHash string) (RefreshToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rt, ok := m.refresh[tokenHash]
	if !ok {
		return RefreshToken{}, ErrNotFound
	}
	return rt, nil
}

func (m *Memory) DeleteRefreshToken(_ context.Context, tokenHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.refresh, tokenHash)
	return nil
}

func (m *Memory) MarkRefreshTokenUsed(_ context.Context, tokenHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rt, ok := m.refresh[tokenHash]
	if !ok {
		return ErrNotFound
	}
	rt.Used = true
	m.refresh[tokenHash] = rt
	return nil
}

func (m *Memory) DeleteRefreshTokensForUser(_ context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for hash, rt := range m.refresh {
		if rt.UserID == userID {
			delete(m.refresh, hash)
		}
	}
	return nil
}

func (m *Memory) ListRefreshTokensForUser(_ context.Context, userID string) ([]RefreshToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := time.Now()
	out := make([]RefreshToken, 0)
	for _, rt := range m.refresh {
		if rt.UserID == userID && !rt.Used && rt.ExpiresAt.After(now) {
			out = append(out, rt)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *Memory) CreateShare(_ context.Context, s Share) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.shares[s.ID]; exists {
		return ErrConflict
	}
	m.shares[s.ID] = s
	return nil
}

func (m *Memory) ListSharesForRecipient(_ context.Context, recipientUserID string) ([]Share, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Share, 0)
	for _, s := range m.shares {
		if s.RecipientUserID == recipientUserID {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *Memory) DeleteShare(_ context.Context, userID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.shares[id]
	if !ok || (s.RecipientUserID != userID && s.OwnerUserID != userID) {
		return ErrNotFound
	}
	delete(m.shares, id)
	return nil
}

func (m *Memory) AppendAuditEvent(_ context.Context, e AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.audit = append(m.audit, e)
	return nil
}

func (m *Memory) ListAuditEvents(_ context.Context, userID string, limit int) ([]AuditEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]AuditEvent, 0, limit)
	// Walk newest-first and collect up to limit events for the user.
	for i := len(m.audit) - 1; i >= 0 && len(out) < limit; i-- {
		if m.audit[i].UserID == userID {
			out = append(out, m.audit[i])
		}
	}
	return out, nil
}

func (m *Memory) Close() error { return nil }
