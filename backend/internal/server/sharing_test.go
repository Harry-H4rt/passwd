package server

import (
	"net/http"
	"testing"
)

func registerWithKey(c *client, id, mph, pub string) {
	c.t.Helper()
	code, _ := c.do("POST", "/api/accounts/register", "", map[string]any{
		"identifier":          id,
		"kdf":                 map[string]any{"type": "argon2id", "iterations": 3, "memoryMiB": 64, "parallelism": 4},
		"masterPasswordHash":  mph,
		"protectedUserKey":    "puk-" + id,
		"publicKey":           pub,
		"protectedPrivateKey": "ppk-" + id,
	})
	if code != http.StatusCreated {
		c.t.Fatalf("register %s: got %d", id, code)
	}
}

func TestItemSharingFlow(t *testing.T) {
	ts := newTestServer(t)
	c := &client{t: t, base: ts.URL}

	registerWithKey(c, "alice@example.com", "mph", "alice-pubkey")
	registerWithKey(c, "bob@example.com", "mph", "bob-pubkey")
	aliceAccess, _ := login(c, "alice@example.com", "mph")
	bobAccess, _ := login(c, "bob@example.com", "mph")

	// Login returns the protected private key so the client can open shares.
	_, lb := c.do("POST", "/api/auth/login", "", map[string]any{
		"identifier": "bob@example.com", "masterPasswordHash": "mph",
	})
	if lb["protectedPrivateKey"] != "ppk-bob@example.com" {
		t.Fatalf("login missing protectedPrivateKey: %v", lb["protectedPrivateKey"])
	}

	// Alice looks up Bob's public key.
	code, body := c.do("GET", "/api/users/public-key?identifier=bob@example.com", aliceAccess, nil)
	if code != http.StatusOK || body["publicKey"] != "bob-pubkey" {
		t.Fatalf("lookup pubkey: %d %v", code, body)
	}
	if code, _ := c.do("GET", "/api/users/public-key?identifier=nobody@example.com", aliceAccess, nil); code != http.StatusNotFound {
		t.Fatalf("lookup unknown pubkey: got %d want 404", code)
	}

	// Alice shares an item with Bob.
	code, body = c.do("POST", "/api/shares", aliceAccess, map[string]any{
		"recipientIdentifier": "bob@example.com", "wrappedKey": "wk-1", "data": "1.aaa|bbb",
	})
	if code != http.StatusCreated {
		t.Fatalf("create share: %d %v", code, body)
	}
	shareID := body["id"].(string)

	// Sharing to an unknown recipient fails.
	if code, _ := c.do("POST", "/api/shares", aliceAccess, map[string]any{
		"recipientIdentifier": "ghost@example.com", "wrappedKey": "x", "data": "y",
	}); code != http.StatusNotFound {
		t.Fatalf("share to unknown: got %d want 404", code)
	}

	// Bob sees the incoming share; Alice (the owner) does not see it as incoming.
	_, bb := c.do("GET", "/api/shares", bobAccess, nil)
	shares, _ := bb["shares"].([]any)
	if len(shares) != 1 {
		t.Fatalf("bob incoming shares = %d; want 1", len(shares))
	}
	got := shares[0].(map[string]any)
	if got["wrappedKey"] != "wk-1" || got["data"] != "1.aaa|bbb" {
		t.Fatalf("share payload mismatch: %v", got)
	}
	_, ab := c.do("GET", "/api/shares", aliceAccess, nil)
	if a, _ := ab["shares"].([]any); len(a) != 0 {
		t.Fatalf("alice incoming shares = %d; want 0", len(a))
	}

	// A third party cannot delete the share; the recipient can.
	registerWithKey(c, "carol@example.com", "mph", "carol-pubkey")
	carolAccess, _ := login(c, "carol@example.com", "mph")
	if code, _ := c.do("DELETE", "/api/shares/"+shareID, carolAccess, nil); code != http.StatusNotFound {
		t.Fatalf("delete by third party: got %d want 404", code)
	}
	if code, _ := c.do("DELETE", "/api/shares/"+shareID, bobAccess, nil); code != http.StatusNoContent {
		t.Fatalf("delete by recipient: got %d want 204", code)
	}
	if _, bb2 := c.do("GET", "/api/shares", bobAccess, nil); len(bb2["shares"].([]any)) != 0 {
		t.Fatal("share not removed")
	}
}
