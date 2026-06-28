package storage

import (
	"context"
	"sync"
)

// Memory is an in-memory Store for tests and ephemeral runs. Not durable.
type Memory struct {
	mu       sync.RWMutex
	users    map[string]User         // id -> User
	byIDHash map[string]string       // identifier hash -> user id
	ciphers  map[string]Cipher       // id -> Cipher
	refresh  map[string]RefreshToken // token hash -> RefreshToken
}

func NewMemory() *Memory {
	return &Memory{
		users:    make(map[string]User),
		byIDHash: make(map[string]string),
		ciphers:  make(map[string]Cipher),
		refresh:  make(map[string]RefreshToken),
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

func (m *Memory) Close() error { return nil }
