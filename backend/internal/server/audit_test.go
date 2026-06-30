package server

import (
	"net/http"
	"testing"
)

// The audit log records a user's own security events (and only theirs), newest
// first, without any plaintext identifier.
func TestAuditLog(t *testing.T) {
	ts := newTestServer(t)
	c := &client{t: t, base: ts.URL}
	register(c, "audit@example.com", "mph")
	access, _ := login(c, "audit@example.com", "mph")

	// A failed login for the (now known) account, and a cipher creation.
	c.do("POST", "/api/auth/login", "", map[string]any{
		"identifier": "audit@example.com", "masterPasswordHash": "wrong",
	})
	if code, _ := c.do("POST", "/api/ciphers", access, map[string]any{"data": "1.aaa|bbb"}); code != http.StatusCreated {
		t.Fatalf("create cipher: got %d", code)
	}

	code, body := c.do("GET", "/api/audit", access, nil)
	if code != http.StatusOK {
		t.Fatalf("audit: got %d", code)
	}
	events, _ := body["events"].([]any)
	seen := map[string]bool{}
	for _, e := range events {
		if m, ok := e.(map[string]any); ok {
			seen[m["event"].(string)] = true
		}
	}
	for _, want := range []string{"account.register", "login.success", "login.failure", "cipher.create"} {
		if !seen[want] {
			t.Errorf("expected audit event %q, got %v", want, seen)
		}
	}
}

// A user's audit log must not include another user's events.
func TestAuditLogIsolatedPerUser(t *testing.T) {
	ts := newTestServer(t)
	c := &client{t: t, base: ts.URL}
	register(c, "alice-audit@example.com", "mph")
	register(c, "bob-audit@example.com", "mph")
	aliceAccess, _ := login(c, "alice-audit@example.com", "mph")
	bobAccess, _ := login(c, "bob-audit@example.com", "mph")

	// Bob creates an item; it must not appear in Alice's log.
	c.do("POST", "/api/ciphers", bobAccess, map[string]any{"data": "1.ccc|ddd"})

	_, body := c.do("GET", "/api/audit", aliceAccess, nil)
	events, _ := body["events"].([]any)
	for _, e := range events {
		if m, ok := e.(map[string]any); ok && m["event"] == "cipher.create" {
			t.Fatalf("alice's audit log leaked another user's cipher.create event")
		}
	}
	// Sanity: Bob does see his own.
	_, bbody := c.do("GET", "/api/audit", bobAccess, nil)
	bevents, _ := bbody["events"].([]any)
	if len(bevents) == 0 {
		t.Fatal("bob's audit log is empty")
	}
}
