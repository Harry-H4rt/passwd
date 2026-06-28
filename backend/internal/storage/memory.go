package storage

import (
	"context"
	"strings"
	"sync"
)

// Memory is an in-memory Store for local development and tests. Single-tenant
// friendly; not durable. Phase 2 adds a SQL-backed implementation.
type Memory struct {
	mu      sync.RWMutex
	users   map[string]User   // id -> User
	byEmail map[string]string // normalized email -> id
	ciphers map[string]Cipher // id -> Cipher
}

func NewMemory() *Memory {
	return &Memory{
		users:   make(map[string]User),
		byEmail: make(map[string]string),
		ciphers: make(map[string]Cipher),
	}
}

var _ Store = (*Memory)(nil)

func normEmail(e string) string { return strings.ToLower(strings.TrimSpace(e)) }

func (m *Memory) CreateUser(_ context.Context, u User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := normEmail(u.Email)
	if _, exists := m.byEmail[key]; exists {
		return ErrConflict
	}
	m.users[u.ID] = u
	m.byEmail[key] = u.ID
	return nil
}

func (m *Memory) GetUserByEmail(_ context.Context, email string) (User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.byEmail[normEmail(email)]
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
