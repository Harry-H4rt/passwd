package server

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/passwd-app/server/internal/config"
	"github.com/passwd-app/server/internal/storage"
)

// End-to-end exercise of the zero-knowledge sync API against a real temp SQLite
// DB. The server treats masterPasswordHash / protectedUserKey / cipher data as
// opaque strings, so the test needs no real crypto — it verifies auth, token
// issuance/rotation, owner isolation, and CRUD/sync.

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	store, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	cfg := config.Config{
		Environment:         "test",
		JWTSecret:           "test-secret",
		IdentifierPepper:    "test-pepper",
		AuthRateLimitPerMin: 10000, // don't rate-limit the test client
	}
	srv := New(cfg, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ts := httptest.NewServer(srv.Routes())
	t.Cleanup(ts.Close)
	return ts
}

type client struct {
	t    *testing.T
	base string
}

func (c *client) do(method, path, token string, body any) (int, map[string]any) {
	c.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rdr)
	if err != nil {
		c.t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatalf("do %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	if len(bytes.TrimSpace(raw)) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return resp.StatusCode, out
}

func register(c *client, id, mph string) {
	c.t.Helper()
	code, _ := c.do("POST", "/api/accounts/register", "", map[string]any{
		"identifier":         id,
		"kdf":                map[string]any{"type": "argon2id", "iterations": 3, "memoryMiB": 64, "parallelism": 4},
		"masterPasswordHash": mph,
		"protectedUserKey":   "puk-" + id,
	})
	if code != http.StatusCreated {
		c.t.Fatalf("register %s: got %d", id, code)
	}
}

func login(c *client, id, mph string) (access, refresh string) {
	c.t.Helper()
	code, body := c.do("POST", "/api/auth/login", "", map[string]any{
		"identifier": id, "masterPasswordHash": mph,
	})
	if code != http.StatusOK {
		c.t.Fatalf("login %s: got %d", id, code)
	}
	return body["accessToken"].(string), body["refreshToken"].(string)
}

func TestFullFlow(t *testing.T) {
	ts := newTestServer(t)
	c := &client{t: t, base: ts.URL}

	// health
	if code, body := c.do("GET", "/healthz", "", nil); code != 200 || body["status"] != "ok" {
		t.Fatalf("healthz: %d %v", code, body)
	}

	// register + duplicate
	register(c, "alice@example.com", "mph-alice")
	if code, _ := c.do("POST", "/api/accounts/register", "", map[string]any{
		"identifier": "ALICE@example.com ", "masterPasswordHash": "x", "protectedUserKey": "y",
	}); code != http.StatusConflict {
		t.Fatalf("duplicate register (normalized): got %d want 409", code)
	}

	// prelogin returns stored KDF; unknown returns default (no oracle)
	if code, body := c.do("POST", "/api/accounts/prelogin", "", map[string]any{"identifier": "alice@example.com"}); code != 200 {
		t.Fatalf("prelogin: %d", code)
	} else if kdf := body["kdf"].(map[string]any); kdf["type"] != "argon2id" {
		t.Fatalf("prelogin kdf: %v", kdf)
	}
	if code, body := c.do("POST", "/api/accounts/prelogin", "", map[string]any{"identifier": "ghost@nowhere"}); code != 200 || body["kdf"].(map[string]any)["type"] != "argon2id" {
		t.Fatalf("prelogin unknown should return default kdf: %d %v", code, body)
	}

	// wrong password rejected
	if code, _ := c.do("POST", "/api/auth/login", "", map[string]any{"identifier": "alice@example.com", "masterPasswordHash": "wrong"}); code != http.StatusUnauthorized {
		t.Fatalf("wrong password: got %d want 401", code)
	}

	// login succeeds, returns protected user key
	access, refresh := login(c, "alice@example.com", "mph-alice")
	if code, body := c.do("POST", "/api/auth/login", "", map[string]any{"identifier": "alice@example.com", "masterPasswordHash": "mph-alice"}); code != 200 || body["protectedUserKey"] != "puk-alice@example.com" {
		t.Fatalf("login protectedUserKey: %d %v", code, body)
	}

	// protected route without token -> 401
	if code, _ := c.do("GET", "/api/sync", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("sync without token: got %d want 401", code)
	}

	// create + sync
	code, item := c.do("POST", "/api/ciphers", access, map[string]any{"data": "1.enc|alice-item"})
	if code != http.StatusCreated {
		t.Fatalf("create cipher: %d", code)
	}
	cipherID := item["id"].(string)
	if code, body := c.do("GET", "/api/sync", access, nil); code != 200 {
		t.Fatalf("sync: %d", code)
	} else if ciphers := body["ciphers"].([]any); len(ciphers) != 1 || ciphers[0].(map[string]any)["data"] != "1.enc|alice-item" {
		t.Fatalf("sync ciphers: %v", body["ciphers"])
	}

	// update
	if code, _ := c.do("PUT", "/api/ciphers/"+cipherID, access, map[string]any{"data": "1.enc|alice-updated"}); code != 200 {
		t.Fatalf("update cipher: %d", code)
	}

	// owner isolation: bob cannot see or delete alice's cipher
	register(c, "bob@example.com", "mph-bob")
	bobAccess, _ := login(c, "bob@example.com", "mph-bob")
	if code, body := c.do("GET", "/api/sync", bobAccess, nil); code != 200 || len(body["ciphers"].([]any)) != 0 {
		t.Fatalf("bob should see no ciphers: %d %v", code, body)
	}
	if code, _ := c.do("DELETE", "/api/ciphers/"+cipherID, bobAccess, nil); code != http.StatusNotFound {
		t.Fatalf("bob delete alice cipher: got %d want 404", code)
	}

	// refresh rotates: old refresh token becomes invalid
	code, rbody := c.do("POST", "/api/auth/refresh", "", map[string]any{"refreshToken": refresh})
	if code != 200 {
		t.Fatalf("refresh: %d", code)
	}
	newAccess := rbody["accessToken"].(string)
	if code, _ := c.do("POST", "/api/auth/refresh", "", map[string]any{"refreshToken": refresh}); code != http.StatusUnauthorized {
		t.Fatalf("reused refresh token: got %d want 401", code)
	}
	// the new access token still works
	if code, _ := c.do("GET", "/api/sync", newAccess, nil); code != 200 {
		t.Fatalf("sync with rotated access token: %d", code)
	}

	// delete + verify gone
	if code, _ := c.do("DELETE", "/api/ciphers/"+cipherID, access, nil); code != http.StatusNoContent {
		t.Fatalf("delete cipher: %d", code)
	}
	if code, body := c.do("GET", "/api/sync", access, nil); code != 200 || len(body["ciphers"].([]any)) != 0 {
		t.Fatalf("after delete, sync should be empty: %d %v", code, body)
	}
}
