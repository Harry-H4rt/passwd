package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testStores returns one of each Store implementation to run a shared contract
// against, so the in-memory double, SQLite, and Postgres can't drift apart.
// Postgres is included only when PASSWD_TEST_POSTGRES_DSN is set (e.g. a throwaway
// container); its tables are truncated for isolation.
func testStores(t *testing.T) map[string]Store {
	t.Helper()
	stores := map[string]Store{"memory": NewMemory()}

	sq, err := OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { sq.Close() })
	stores["sqlite"] = sq

	if dsn := os.Getenv("PASSWD_TEST_POSTGRES_DSN"); dsn != "" {
		pg, err := OpenPostgres(dsn)
		if err != nil {
			t.Fatalf("open postgres: %v", err)
		}
		if _, err := pg.db.ExecContext(context.Background(),
			`TRUNCATE users, ciphers, refresh_tokens, webauthn_credentials, audit_events, shares`); err != nil {
			t.Fatalf("truncate postgres: %v", err)
		}
		t.Cleanup(func() { pg.Close() })
		stores["postgres"] = pg
	}
	return stores
}

func TestStoreContract(t *testing.T) {
	for name, st := range testStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Second)

			// --- users ---
			u := User{
				ID: "u1", IdentifierHash: "idh-1",
				KDF:                    KDFParams{Type: "argon2id", Iterations: 3, MemoryMiB: 64, Parallelism: 4},
				MasterPasswordVerifier: "verify-1", ProtectedUserKey: "puk-1",
				PublicKey: "pub-1", ProtectedPrivateKey: "ppk-1",
				CreatedAt: now, UpdatedAt: now,
			}
			if err := st.CreateUser(ctx, u); err != nil {
				t.Fatalf("create user: %v", err)
			}
			dup := u
			dup.ID = "u1b" // same identifier hash
			if err := st.CreateUser(ctx, dup); !errors.Is(err, ErrConflict) {
				t.Fatalf("duplicate identifier = %v; want ErrConflict", err)
			}
			got, err := st.GetUserByID(ctx, "u1")
			if err != nil || got.ProtectedUserKey != "puk-1" || got.KDF.MemoryMiB != 64 {
				t.Fatalf("get user: %+v, %v", got, err)
			}
			if got.PublicKey != "pub-1" || got.ProtectedPrivateKey != "ppk-1" {
				t.Fatalf("keypair round-trip: %+v", got)
			}
			if byHash, err := st.GetUserByIdentifierHash(ctx, "idh-1"); err != nil || byHash.ID != "u1" {
				t.Fatalf("get by identifier hash: %+v, %v", byHash, err)
			}
			if _, err := st.GetUserByID(ctx, "missing"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("missing user = %v; want ErrNotFound", err)
			}

			// --- TOTP secret + replay counter ---
			if err := st.SetUserTOTP(ctx, "u1", "enc-secret", true); err != nil {
				t.Fatal(err)
			}
			if err := st.SetUserTOTPCounter(ctx, "u1", 12345); err != nil {
				t.Fatal(err)
			}
			got, _ = st.GetUserByID(ctx, "u1")
			if !got.TOTPEnabled || got.TOTPSecret != "enc-secret" || got.TOTPLastCounter != 12345 {
				t.Fatalf("totp state: %+v", got)
			}
			// Changing the secret resets the replay baseline.
			if err := st.SetUserTOTP(ctx, "u1", "enc-2", true); err != nil {
				t.Fatal(err)
			}
			if got, _ = st.GetUserByID(ctx, "u1"); got.TOTPLastCounter != 0 {
				t.Fatalf("counter not reset on secret change: %d", got.TOTPLastCounter)
			}

			// --- recovery set / clear ---
			if err := st.SetUserRecovery(ctx, "u1", "rpuk", "rverify"); err != nil {
				t.Fatal(err)
			}
			if got, _ = st.GetUserByID(ctx, "u1"); got.RecoveryProtectedUserKey != "rpuk" || got.RecoveryVerifier != "rverify" {
				t.Fatalf("recovery set: %+v", got)
			}
			if err := st.ClearUserRecovery(ctx, "u1"); err != nil {
				t.Fatal(err)
			}
			if got, _ = st.GetUserByID(ctx, "u1"); got.RecoveryVerifier != "" {
				t.Fatalf("recovery not cleared: %+v", got)
			}

			// --- master-password rotation ---
			newKDF := KDFParams{Type: "pbkdf2", Iterations: 600000}
			if err := st.RotateMasterPassword(ctx, "u1", "verify-2", "puk-2", newKDF); err != nil {
				t.Fatal(err)
			}
			if got, _ = st.GetUserByID(ctx, "u1"); got.MasterPasswordVerifier != "verify-2" || got.ProtectedUserKey != "puk-2" || got.KDF.Type != "pbkdf2" {
				t.Fatalf("rotate: %+v", got)
			}

			// --- ciphers: CRUD + owner isolation ---
			if err := st.CreateCipher(ctx, Cipher{ID: "c1", UserID: "u1", Data: "d1", CreatedAt: now, UpdatedAt: now}); err != nil {
				t.Fatal(err)
			}
			if err := st.UpdateCipher(ctx, Cipher{ID: "c1", UserID: "u1", Data: "d1b", UpdatedAt: now}); err != nil {
				t.Fatal(err)
			}
			if err := st.UpdateCipher(ctx, Cipher{ID: "c1", UserID: "other", Data: "x", UpdatedAt: now}); !errors.Is(err, ErrNotFound) {
				t.Fatalf("cross-owner update = %v; want ErrNotFound", err)
			}
			if list, _ := st.ListCiphers(ctx, "u1"); len(list) != 1 || list[0].Data != "d1b" {
				t.Fatalf("list ciphers: %+v", list)
			}
			if err := st.DeleteCipher(ctx, "other", "c1"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("cross-owner delete = %v; want ErrNotFound", err)
			}
			if err := st.DeleteCipher(ctx, "u1", "c1"); err != nil {
				t.Fatal(err)
			}

			// --- refresh tokens: rotation + reuse + bulk revoke ---
			if err := st.CreateRefreshToken(ctx, RefreshToken{TokenHash: "h1", UserID: "u1", ExpiresAt: now.Add(time.Hour), CreatedAt: now}); err != nil {
				t.Fatal(err)
			}
			if g, err := st.GetRefreshToken(ctx, "h1"); err != nil || g.Used {
				t.Fatalf("get refresh: %+v, %v", g, err)
			}
			if err := st.MarkRefreshTokenUsed(ctx, "h1"); err != nil {
				t.Fatal(err)
			}
			if g, _ := st.GetRefreshToken(ctx, "h1"); !g.Used {
				t.Fatal("refresh token not marked used")
			}
			_ = st.CreateRefreshToken(ctx, RefreshToken{TokenHash: "h2", UserID: "u1", ExpiresAt: now.Add(time.Hour), CreatedAt: now})
			if err := st.DeleteRefreshTokensForUser(ctx, "u1"); err != nil {
				t.Fatal(err)
			}
			for _, h := range []string{"h1", "h2"} {
				if _, err := st.GetRefreshToken(ctx, h); !errors.Is(err, ErrNotFound) {
					t.Fatalf("refresh %s after bulk revoke = %v; want ErrNotFound", h, err)
				}
			}

			// --- shares: create, list-for-recipient, owner/recipient delete ---
			if err := st.CreateShare(ctx, Share{ID: "s1", OwnerUserID: "u1", RecipientUserID: "u2", WrappedKey: "wk", Data: "dt", CreatedAt: now}); err != nil {
				t.Fatal(err)
			}
			if recv, _ := st.ListSharesForRecipient(ctx, "u2"); len(recv) != 1 || recv[0].WrappedKey != "wk" {
				t.Fatalf("list shares for recipient: %+v", recv)
			}
			if owned, _ := st.ListSharesForRecipient(ctx, "u1"); len(owned) != 0 {
				t.Fatalf("owner should not see it as incoming: %+v", owned)
			}
			if err := st.DeleteShare(ctx, "stranger", "s1"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("delete by stranger = %v; want ErrNotFound", err)
			}
			if err := st.DeleteShare(ctx, "u1", "s1"); err != nil { // owner may delete
				t.Fatalf("owner delete: %v", err)
			}

			// --- audit log: append, newest-first, per-user isolation ---
			_ = st.AppendAuditEvent(ctx, AuditEvent{ID: "a1", UserID: "u1", Event: "login.success", CreatedAt: now})
			_ = st.AppendAuditEvent(ctx, AuditEvent{ID: "a2", UserID: "u1", Event: "cipher.create", Detail: "c1", CreatedAt: now.Add(time.Second)})
			_ = st.AppendAuditEvent(ctx, AuditEvent{ID: "a3", UserID: "other", Event: "login.success", CreatedAt: now})
			ev, err := st.ListAuditEvents(ctx, "u1", 10)
			if err != nil || len(ev) != 2 {
				t.Fatalf("audit list = %d, %v; want 2", len(ev), err)
			}
			if ev[0].Event != "cipher.create" {
				t.Fatalf("audit not newest-first: %+v", ev)
			}

			// --- account deletion: cascade across every table + user isolation ---
			del := User{
				ID: "del1", IdentifierHash: "idh-del1",
				KDF:                    KDFParams{Type: "argon2id", Iterations: 3, MemoryMiB: 64, Parallelism: 4},
				MasterPasswordVerifier: "v", ProtectedUserKey: "puk", PublicKey: "pub", ProtectedPrivateKey: "ppk",
				CreatedAt: now, UpdatedAt: now,
			}
			if err := st.CreateUser(ctx, del); err != nil {
				t.Fatalf("create del user: %v", err)
			}
			_ = st.CreateCipher(ctx, Cipher{ID: "dc1", UserID: "del1", Data: "d", CreatedAt: now, UpdatedAt: now})
			_ = st.CreateRefreshToken(ctx, RefreshToken{TokenHash: "dh1", UserID: "del1", ExpiresAt: now.Add(time.Hour), CreatedAt: now})
			_ = st.CreateWebAuthnCredential(ctx, WebAuthnCredential{ID: "dp1", UserID: "del1", CredentialID: []byte("cred-del1"), PublicKey: []byte("pk"), CreatedAt: now, UpdatedAt: now})
			_ = st.AppendAuditEvent(ctx, AuditEvent{ID: "da1", UserID: "del1", Event: "login.success", CreatedAt: now})
			_ = st.CreateShare(ctx, Share{ID: "ds1", OwnerUserID: "del1", RecipientUserID: "u2", WrappedKey: "wk", Data: "dt", CreatedAt: now})   // owned
			_ = st.CreateShare(ctx, Share{ID: "ds2", OwnerUserID: "other", RecipientUserID: "del1", WrappedKey: "wk", Data: "dt", CreatedAt: now}) // received

			if err := st.DeleteAccount(ctx, "del1"); err != nil {
				t.Fatalf("delete account: %v", err)
			}
			if _, err := st.GetUserByID(ctx, "del1"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("user after delete = %v; want ErrNotFound", err)
			}
			if c, _ := st.ListCiphers(ctx, "del1"); len(c) != 0 {
				t.Fatalf("ciphers after delete: %+v", c)
			}
			if _, err := st.GetRefreshToken(ctx, "dh1"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("refresh after delete = %v; want ErrNotFound", err)
			}
			if pk, _ := st.ListWebAuthnCredentials(ctx, "del1"); len(pk) != 0 {
				t.Fatalf("passkeys after delete: %+v", pk)
			}
			if a, _ := st.ListAuditEvents(ctx, "del1", 10); len(a) != 0 {
				t.Fatalf("audit after delete: %+v", a)
			}
			if in, _ := st.ListSharesForRecipient(ctx, "del1"); len(in) != 0 {
				t.Fatalf("received shares after delete: %+v", in)
			}
			if out, _ := st.ListSharesForRecipient(ctx, "u2"); len(out) != 0 {
				t.Fatalf("owned share not removed on owner delete: %+v", out)
			}
			// Other users are untouched.
			if _, err := st.GetUserByID(ctx, "u1"); err != nil {
				t.Fatalf("u1 wrongly affected by del1 deletion: %v", err)
			}
			if a, _ := st.ListAuditEvents(ctx, "u1", 10); len(a) != 2 {
				t.Fatalf("u1 audit wrongly affected: %d; want 2", len(a))
			}
			// Deleting a missing account is reported, not silent.
			if err := st.DeleteAccount(ctx, "del1"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("delete missing account = %v; want ErrNotFound", err)
			}
		})
	}
}
