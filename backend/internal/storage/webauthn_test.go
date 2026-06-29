package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// Runs the same passkey-storage contract against both Store implementations so the
// in-memory test double can't drift from the durable SQLite behaviour.
func TestWebAuthnCredentialStores(t *testing.T) {
	stores := map[string]func(t *testing.T) Store{
		"memory": func(t *testing.T) Store { return NewMemory() },
		"sqlite": func(t *testing.T) Store {
			s, err := OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
			if err != nil {
				t.Fatalf("open sqlite: %v", err)
			}
			t.Cleanup(func() { s.Close() })
			return s
		},
	}
	for name, mk := range stores {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			st := mk(t)

			now := time.Now().UTC().Truncate(time.Second)
			cred := WebAuthnCredential{
				ID:           "row-1",
				UserID:       "user-1",
				CredentialID: []byte{0x01, 0x02, 0x03},
				PublicKey:    []byte("cose-public-key"),
				Transports:   `["usb","nfc"]`,
				AAGUID:       []byte{0xaa, 0xbb},
				SignCount:    0,
				Name:         "YubiKey 5",
				CreatedAt:    now,
				UpdatedAt:    now,
			}

			if n, err := st.CountWebAuthnCredentials(ctx, "user-1"); err != nil || n != 0 {
				t.Fatalf("count before insert = %d, %v; want 0", n, err)
			}
			if err := st.CreateWebAuthnCredential(ctx, cred); err != nil {
				t.Fatalf("create: %v", err)
			}

			// Same credential ID can't be enrolled twice (even by another user).
			dup := cred
			dup.ID = "row-2"
			dup.UserID = "user-2"
			if err := st.CreateWebAuthnCredential(ctx, dup); !errors.Is(err, ErrConflict) {
				t.Fatalf("duplicate credential_id = %v; want ErrConflict", err)
			}

			list, err := st.ListWebAuthnCredentials(ctx, "user-1")
			if err != nil || len(list) != 1 {
				t.Fatalf("list = %d, %v; want 1", len(list), err)
			}
			got := list[0]
			if got.Name != "YubiKey 5" || string(got.PublicKey) != "cose-public-key" ||
				got.Transports != `["usb","nfc"]` || string(got.CredentialID) != "\x01\x02\x03" {
				t.Fatalf("round-trip mismatch: %+v", got)
			}

			if n, err := st.CountWebAuthnCredentials(ctx, "user-1"); err != nil || n != 1 {
				t.Fatalf("count after insert = %d, %v; want 1", n, err)
			}

			// Sign count advances by credential ID, not row ID.
			if err := st.UpdateWebAuthnSignCount(ctx, cred.CredentialID, 42); err != nil {
				t.Fatalf("update sign count: %v", err)
			}
			list, _ = st.ListWebAuthnCredentials(ctx, "user-1")
			if list[0].SignCount != 42 {
				t.Fatalf("sign count = %d; want 42", list[0].SignCount)
			}
			if err := st.UpdateWebAuthnSignCount(ctx, []byte("nope"), 1); !errors.Is(err, ErrNotFound) {
				t.Fatalf("update unknown credential = %v; want ErrNotFound", err)
			}

			// Delete is owner-scoped.
			if err := st.DeleteWebAuthnCredential(ctx, "user-2", "row-1"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("delete by wrong owner = %v; want ErrNotFound", err)
			}
			if err := st.DeleteWebAuthnCredential(ctx, "user-1", "row-1"); err != nil {
				t.Fatalf("delete: %v", err)
			}
			if n, _ := st.CountWebAuthnCredentials(ctx, "user-1"); n != 0 {
				t.Fatalf("count after delete = %d; want 0", n)
			}
		})
	}
}
