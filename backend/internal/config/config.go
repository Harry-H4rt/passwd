// Package config loads runtime configuration from the environment.
package config

import (
	"os"
	"strconv"
)

type Config struct {
	Addr        string // listen address, e.g. ":8080"
	Environment string // "development" | "production"
	JWTSecret   string // signing secret for access tokens
	DBPath      string // SQLite file path; "" or "memory" -> in-memory store
	// IdentifierPepper is a server-side secret mixed into the HMAC that blinds the
	// account identifier. Keeps a DB leak from confirming guessed identifiers.
	IdentifierPepper string
	// AuthRateLimitPerMin caps auth requests per client IP per minute. The real
	// brute-force defense is the per-account lockout; this is NAT-friendly spam
	// protection, so keep it generous.
	AuthRateLimitPerMin int
}

func Load() Config {
	return Config{
		Addr:                getenv("PASSWD_ADDR", ":8080"),
		Environment:         getenv("PASSWD_ENV", "development"),
		JWTSecret:           getenv("PASSWD_JWT_SECRET", "dev-only-insecure-secret-change-me"),
		DBPath:              getenv("PASSWD_DB", "data/passwd.db"),
		IdentifierPepper:    getenv("PASSWD_IDENTIFIER_PEPPER", "dev-only-insecure-pepper-change-me"),
		AuthRateLimitPerMin: getenvInt("PASSWD_AUTH_RATELIMIT_PER_MIN", 60),
	}
}

func (c Config) IsProduction() bool { return c.Environment == "production" }

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}
