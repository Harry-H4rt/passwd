package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/passwd-app/server/internal/auth"
	"github.com/passwd-app/server/internal/storage"
)

// seedPasskey enrolls a passkey straight into the store for the account behind id.
// The registration ceremony needs a real authenticator (covered by manual e2e), so
// these tests seed the credential and exercise the surrounding wiring: the login
// method list and the assertion begin endpoints.
func seedPasskey(t *testing.T, store storage.Store, id string, credID []byte) {
	t.Helper()
	idHash := auth.BlindIdentifier("test-pepper", id)
	u, err := store.GetUserByIdentifierHash(context.Background(), idHash)
	if err != nil {
		t.Fatalf("lookup user %s: %v", id, err)
	}
	now := time.Now().UTC()
	if err := store.CreateWebAuthnCredential(context.Background(), storage.WebAuthnCredential{
		ID:           "pk-" + id,
		UserID:       u.ID,
		CredentialID: credID,
		PublicKey:    []byte("test-public-key"),
		Name:         "Test passkey",
		CreatedAt:    now,
		UpdatedAt:    now,
	}); err != nil {
		t.Fatalf("seed passkey: %v", err)
	}
}

func methodsOf(body map[string]any) map[string]bool {
	out := map[string]bool{}
	raw, _ := body["methods"].([]any)
	for _, m := range raw {
		if s, ok := m.(string); ok {
			out[s] = true
		}
	}
	return out
}

func TestLoginAdvertisesWebAuthnMethod(t *testing.T) {
	ts, store := newTestServerStore(t)
	c := &client{t: t, base: ts.URL}
	register(c, "alice", "hash-alice")
	seedPasskey(t, store, "alice", []byte("cred-alice"))

	// Password is correct but a second factor is enrolled: 401 + the method list.
	code, body := c.do("POST", "/api/auth/login", "", map[string]any{
		"identifier": "alice", "masterPasswordHash": "hash-alice",
	})
	if code != http.StatusUnauthorized {
		t.Fatalf("login status = %d; want 401", code)
	}
	if body["twoFactorRequired"] != true {
		t.Fatalf("twoFactorRequired = %v; want true", body["twoFactorRequired"])
	}
	methods := methodsOf(body)
	if !methods["webauthn"] || methods["totp"] {
		t.Fatalf("methods = %v; want [webauthn] only", body["methods"])
	}
}

func TestLoginAdvertisesBothFactors(t *testing.T) {
	ts, store := newTestServerStore(t)
	c := &client{t: t, base: ts.URL}
	register(c, "bob", "hash-bob")
	seedPasskey(t, store, "bob", []byte("cred-bob"))

	// Also enable TOTP directly.
	idHash := auth.BlindIdentifier("test-pepper", "bob")
	u, _ := store.GetUserByIdentifierHash(context.Background(), idHash)
	secret, _ := auth.GenerateTOTPSecret()
	if err := store.SetUserTOTP(context.Background(), u.ID, secret, true); err != nil {
		t.Fatalf("enable totp: %v", err)
	}

	_, body := c.do("POST", "/api/auth/login", "", map[string]any{
		"identifier": "bob", "masterPasswordHash": "hash-bob",
	})
	methods := methodsOf(body)
	if !methods["webauthn"] || !methods["totp"] {
		t.Fatalf("methods = %v; want both webauthn and totp", body["methods"])
	}
}

func TestWebAuthnRegisterBeginRequiresAuth(t *testing.T) {
	ts := newTestServer(t)
	c := &client{t: t, base: ts.URL}
	code, _ := c.do("POST", "/api/2fa/webauthn/register/begin", "", nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401 without a token", code)
	}
}

func TestWebAuthnRegisterBeginReturnsOptions(t *testing.T) {
	ts := newTestServer(t)
	c := &client{t: t, base: ts.URL}
	register(c, "carol", "hash-carol")
	access, _ := login(c, "carol", "hash-carol")

	code, body := c.do("POST", "/api/2fa/webauthn/register/begin", access, nil)
	if code != http.StatusOK {
		t.Fatalf("status = %d; want 200", code)
	}
	if _, ok := body["sessionId"].(string); !ok {
		t.Fatalf("response missing sessionId: %v", body)
	}
	opts, ok := body["options"].(map[string]any)
	if !ok {
		t.Fatalf("response missing options: %v", body)
	}
	if _, ok := opts["publicKey"]; !ok {
		t.Fatalf("options missing publicKey: %v", opts)
	}
}

func TestWebAuthnLoginBegin(t *testing.T) {
	ts, store := newTestServerStore(t)
	c := &client{t: t, base: ts.URL}
	register(c, "dave", "hash-dave")
	seedPasskey(t, store, "dave", []byte("cred-dave"))

	// Wrong password gets the generic 401.
	code, _ := c.do("POST", "/api/auth/webauthn/begin", "", map[string]any{
		"identifier": "dave", "masterPasswordHash": "wrong",
	})
	if code != http.StatusUnauthorized {
		t.Fatalf("wrong-password status = %d; want 401", code)
	}

	// Correct password returns an assertion challenge.
	code, body := c.do("POST", "/api/auth/webauthn/begin", "", map[string]any{
		"identifier": "dave", "masterPasswordHash": "hash-dave",
	})
	if code != http.StatusOK {
		t.Fatalf("status = %d; want 200", code)
	}
	if _, ok := body["sessionId"].(string); !ok {
		t.Fatalf("response missing sessionId: %v", body)
	}
	opts, ok := body["options"].(map[string]any)
	if !ok {
		t.Fatalf("response missing options: %v", body)
	}
	if _, ok := opts["publicKey"]; !ok {
		t.Fatalf("options missing publicKey: %v", opts)
	}
}
