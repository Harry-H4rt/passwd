package server

import (
	"net/http"
	"testing"
)

// Exercises the account-recovery flow end to end. As elsewhere, the server treats
// the recovery-wrapped key and the recovery auth hash as opaque strings, so the
// test needs no real crypto — it verifies enrollment, the challenge/complete
// handshake, master-password rotation, and the lockout/oracle behaviour.

func TestRecoveryFlow(t *testing.T) {
	ts := newTestServer(t)
	c := &client{t: t, base: ts.URL}
	const id = "alice@example.com"

	register(c, id, "mph-1")
	access, _ := login(c, id, "mph-1")

	// Recovery is off until enrolled.
	if code, body := c.do("GET", "/api/recovery", access, nil); code != http.StatusOK || body["enabled"] != false {
		t.Fatalf("status before enroll: code=%d body=%v", code, body)
	}

	// Enroll (done client-side while unlocked).
	if code, _ := c.do("POST", "/api/recovery/enable", access, map[string]any{
		"recoveryProtectedUserKey": "rpuk-alice",
		"recoveryAuthHash":         "rauth-alice",
	}); code != http.StatusNoContent {
		t.Fatalf("enable recovery: got %d", code)
	}
	if code, body := c.do("GET", "/api/recovery", access, nil); code != http.StatusOK || body["enabled"] != true {
		t.Fatalf("status after enroll: code=%d body=%v", code, body)
	}

	// Challenge returns the recovery-wrapped key so the client can unwrap it.
	code, body := c.do("POST", "/api/auth/recovery/challenge", "", map[string]any{"identifier": id})
	if code != http.StatusOK || body["recoveryProtectedUserKey"] != "rpuk-alice" {
		t.Fatalf("challenge: code=%d body=%v", code, body)
	}

	// Wrong recovery code is rejected.
	if code, _ := c.do("POST", "/api/auth/recovery/complete", "", map[string]any{
		"identifier": id, "recoveryAuthHash": "wrong", "masterPasswordHash": "mph-x", "protectedUserKey": "puk-x",
	}); code != http.StatusUnauthorized {
		t.Fatalf("complete with wrong code: got %d want 401", code)
	}

	// Correct recovery code rotates the master password and logs the user in.
	code, body = c.do("POST", "/api/auth/recovery/complete", "", map[string]any{
		"identifier": id, "recoveryAuthHash": "rauth-alice",
		"masterPasswordHash": "mph-2", "protectedUserKey": "puk-2",
		"kdf": map[string]any{"type": "argon2id", "iterations": 3, "memoryMiB": 64, "parallelism": 4},
	})
	if code != http.StatusOK {
		t.Fatalf("complete recovery: got %d body=%v", code, body)
	}
	if body["accessToken"] == nil || body["protectedUserKey"] != "puk-2" {
		t.Fatalf("complete response missing tokens/key: %v", body)
	}

	// The old master password no longer works; the new one does.
	if code, _ := c.do("POST", "/api/auth/login", "", map[string]any{
		"identifier": id, "masterPasswordHash": "mph-1",
	}); code != http.StatusUnauthorized {
		t.Fatalf("login with old password: got %d want 401", code)
	}
	access2, _ := login(c, id, "mph-2")
	if access2 == "" {
		t.Fatal("login with new password returned no token")
	}

	// Disabling recovery clears it.
	if code, _ := c.do("POST", "/api/recovery/disable", access2, nil); code != http.StatusNoContent {
		t.Fatalf("disable recovery: got %d", code)
	}
	if _, b := c.do("GET", "/api/recovery", access2, nil); b["enabled"] != false {
		t.Fatalf("status after disable: %v", b)
	}
}

// An unknown identifier must not be distinguishable via the challenge: it returns
// a well-formed decoy blob rather than an empty/sentinel value.
func TestRecoveryChallengeNoOracle(t *testing.T) {
	ts := newTestServer(t)
	c := &client{t: t, base: ts.URL}

	code, body := c.do("POST", "/api/auth/recovery/challenge", "", map[string]any{"identifier": "nobody@example.com"})
	if code != http.StatusOK {
		t.Fatalf("challenge unknown: got %d", code)
	}
	blob, ok := body["recoveryProtectedUserKey"].(string)
	if !ok || blob == "" {
		t.Fatalf("expected a decoy blob, got %v", body["recoveryProtectedUserKey"])
	}
	if body["kdf"] == nil {
		t.Fatalf("expected default kdf in challenge response, got %v", body)
	}
}
