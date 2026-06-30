package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/passwd-app/server/internal/auth"
	"github.com/passwd-app/server/internal/config"
	"github.com/passwd-app/server/internal/storage"
)

// Reusing a rotated refresh token is treated as theft: the whole session family is
// revoked, so neither the replayed token nor its successor works afterwards.
func TestRefreshTokenReuseRevokesSessions(t *testing.T) {
	ts := newTestServer(t)
	c := &client{t: t, base: ts.URL}
	register(c, "reuse@example.com", "mph")
	_, refresh := login(c, "reuse@example.com", "mph")

	// First rotation succeeds and yields a successor token.
	code, body := c.do("POST", "/api/auth/refresh", "", map[string]any{"refreshToken": refresh})
	if code != http.StatusOK {
		t.Fatalf("first refresh: got %d", code)
	}
	successor := body["refreshToken"].(string)

	// Replaying the original (now-used) token is rejected as reuse.
	if code, _ := c.do("POST", "/api/auth/refresh", "", map[string]any{"refreshToken": refresh}); code != http.StatusUnauthorized {
		t.Fatalf("reused token: got %d want 401", code)
	}

	// Reuse detection revoked the whole family, so the successor is dead too.
	if code, _ := c.do("POST", "/api/auth/refresh", "", map[string]any{"refreshToken": successor}); code != http.StatusUnauthorized {
		t.Fatalf("successor after reuse: got %d want 401", code)
	}
}

// A TOTP code is single-use at login: replaying the same code within its validity
// window is rejected even though it would otherwise still be valid.
func TestTOTPReplayRejected(t *testing.T) {
	ts := newTestServer(t)
	c := &client{t: t, base: ts.URL}
	register(c, "replay@example.com", "mph")
	access, _ := login(c, "replay@example.com", "mph")

	_, body := c.do("POST", "/api/2fa/setup", access, map[string]any{})
	secret := body["secret"].(string)
	enableCode, _ := auth.CurrentTOTP(secret)
	if code, _ := c.do("POST", "/api/2fa/enable", access, map[string]any{"code": enableCode}); code != http.StatusOK {
		t.Fatalf("enable: got %d", code)
	}

	code, _ := auth.CurrentTOTP(secret)
	// First login with the code succeeds.
	if status, _ := c.do("POST", "/api/auth/login", "", map[string]any{
		"identifier": "replay@example.com", "masterPasswordHash": "mph", "totpCode": code,
	}); status != http.StatusOK {
		t.Fatalf("first login with code: got %d", status)
	}
	// Replaying the exact same code is rejected.
	if status, _ := c.do("POST", "/api/auth/login", "", map[string]any{
		"identifier": "replay@example.com", "masterPasswordHash": "mph", "totpCode": code,
	}); status != http.StatusUnauthorized {
		t.Fatalf("replayed code: got %d want 401", status)
	}
}

// The TOTP secret is encrypted at rest: what the store holds is neither empty nor
// the plaintext returned to the client.
func TestTOTPSecretEncryptedAtRest(t *testing.T) {
	ts, store := newTestServerStore(t)
	c := &client{t: t, base: ts.URL}
	register(c, "rest@example.com", "mph")
	access, _ := login(c, "rest@example.com", "mph")

	_, body := c.do("POST", "/api/2fa/setup", access, map[string]any{})
	secret := body["secret"].(string)

	idHash := auth.BlindIdentifier("test-pepper", "rest@example.com")
	u, err := store.GetUserByIdentifierHash(context.Background(), idHash)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if u.TOTPSecret == "" || u.TOTPSecret == secret {
		t.Fatalf("stored TOTP secret is not encrypted (%q)", u.TOTPSecret)
	}
	if !strings.Contains(u.TOTPSecret, "|") {
		t.Fatalf("stored TOTP secret is not in the sealed format: %q", u.TOTPSecret)
	}
}

// X-Forwarded-For is honored only when the direct peer is a configured trusted
// proxy; otherwise the connection IP is used (the header is client-spoofable).
func TestClientIPTrustedProxy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(config.Config{TrustedProxies: []string{"10.0.0.1"}}, storage.NewMemory(), logger)

	trusted := httptest.NewRequest(http.MethodPost, "/", nil)
	trusted.RemoteAddr = "10.0.0.1:5000"
	trusted.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
	if got := srv.clientIP(trusted); got != "203.0.113.9" {
		t.Fatalf("trusted proxy XFF: got %q want 203.0.113.9", got)
	}

	spoof := httptest.NewRequest(http.MethodPost, "/", nil)
	spoof.RemoteAddr = "8.8.8.8:1234"
	spoof.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := srv.clientIP(spoof); got != "8.8.8.8" {
		t.Fatalf("untrusted peer must ignore XFF: got %q want 8.8.8.8", got)
	}
}
