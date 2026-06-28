package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetSecretFileTakesPrecedence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jwt")
	if err := os.WriteFile(path, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PASSWD_JWT_SECRET_FILE", path)
	t.Setenv("PASSWD_JWT_SECRET", "env-secret")

	// _FILE wins over the plain env var, and trailing whitespace is trimmed.
	if got := Load().JWTSecret; got != "file-secret" {
		t.Fatalf("JWTSecret = %q, want file-secret", got)
	}
}

func TestGetSecretFallsBackToEnvThenDefault(t *testing.T) {
	t.Setenv("PASSWD_IDENTIFIER_PEPPER_FILE", "")
	t.Setenv("PASSWD_IDENTIFIER_PEPPER", "env-pepper")
	if got := Load().IdentifierPepper; got != "env-pepper" {
		t.Fatalf("IdentifierPepper = %q, want env-pepper", got)
	}

	// Neither set -> the (insecure) dev default, which production startup refuses.
	t.Setenv("PASSWD_JWT_SECRET_FILE", "")
	t.Setenv("PASSWD_JWT_SECRET", "")
	if got := Load().JWTSecret; got != "dev-only-insecure-secret-change-me" {
		t.Fatalf("JWTSecret = %q, want dev default", got)
	}
}

func TestGetSecretMissingFileFallsThrough(t *testing.T) {
	t.Setenv("PASSWD_JWT_SECRET_FILE", filepath.Join(t.TempDir(), "does-not-exist"))
	t.Setenv("PASSWD_JWT_SECRET", "env-secret")
	if got := Load().JWTSecret; got != "env-secret" {
		t.Fatalf("JWTSecret = %q, want env-secret (file missing should fall through)", got)
	}
}
