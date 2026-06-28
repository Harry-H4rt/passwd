// Package vault is the domain service for encrypted vault items. It operates only
// on opaque ciphertext (EncString) scoped to a user — it never sees plaintext and
// stores no item metadata (no type, no name).
package vault

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/passwd-app/server/internal/storage"
)

type Service struct {
	store storage.Store
}

func New(store storage.Store) *Service { return &Service{store: store} }

// Item is the API-facing view of an opaque cipher.
type Item struct {
	ID        string    `json:"id"`
	Data      string    `json:"data"` // EncString
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func toItem(c storage.Cipher) Item {
	return Item{ID: c.ID, Data: c.Data, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt}
}

func (s *Service) Create(ctx context.Context, userID, data string) (Item, error) {
	now := time.Now().UTC()
	c := storage.Cipher{ID: newID(), UserID: userID, Data: data, CreatedAt: now, UpdatedAt: now}
	if err := s.store.CreateCipher(ctx, c); err != nil {
		return Item{}, err
	}
	return toItem(c), nil
}

func (s *Service) Update(ctx context.Context, userID, id, data string) (Item, error) {
	now := time.Now().UTC()
	c := storage.Cipher{ID: id, UserID: userID, Data: data, UpdatedAt: now}
	if err := s.store.UpdateCipher(ctx, c); err != nil {
		return Item{}, err
	}
	// Re-read to return authoritative timestamps would need a Get; the updated
	// fields are sufficient for the client, which already holds CreatedAt.
	return toItem(c), nil
}

func (s *Service) Delete(ctx context.Context, userID, id string) error {
	return s.store.DeleteCipher(ctx, userID, id)
}

func (s *Service) List(ctx context.Context, userID string) ([]Item, error) {
	ciphers, err := s.store.ListCiphers(ctx, userID)
	if err != nil {
		return nil, err
	}
	items := make([]Item, 0, len(ciphers))
	for _, c := range ciphers {
		items = append(items, toItem(c))
	}
	return items, nil
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
