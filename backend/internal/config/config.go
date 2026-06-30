// Package config loads runtime configuration from the environment.
package config

import (
	"os"
	"strconv"
	"strings"
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
	// AllowedOrigins is the CORS allowlist for browser clients on other origins
	// (e.g. the web vault served from a different host). The API is bearer-token
	// based (no cookies), so credentials are not allowed and "*" is unnecessary.
	AllowedOrigins []string
	// WebAuthnRPID is the WebAuthn Relying Party ID: the registrable domain of the
	// vault (host only, no scheme/port), e.g. "vault.example.com". Passkeys are
	// bound to it, so it must stay stable. Defaults to "localhost" for dev.
	WebAuthnRPID string
	// WebAuthnRPName is the human-facing Relying Party name shown by authenticators.
	WebAuthnRPName string
	// WebAuthnRPOrigins are the fully-qualified origins permitted to run passkey
	// ceremonies (e.g. "https://vault.example.com"). Defaults to AllowedOrigins,
	// which is where the web vault is served from.
	WebAuthnRPOrigins []string
	// TrustedProxies lists reverse-proxy IPs whose X-Forwarded-For header is honored
	// for client-IP rate limiting. Empty (the default) means the direct connection
	// IP is always used. Only set this for proxies you control — the header is
	// client-spoofable from any untrusted hop.
	TrustedProxies []string
}

func Load() Config {
	allowedOrigins := splitList(getenv("PASSWD_ALLOWED_ORIGINS", "http://localhost:5173"))
	rpOrigins := splitList(getenv("PASSWD_WEBAUTHN_RP_ORIGINS", ""))
	if len(rpOrigins) == 0 {
		// Default the passkey ceremony origins to wherever the web vault is served.
		rpOrigins = allowedOrigins
	}
	return Config{
		Addr:                getenv("PASSWD_ADDR", ":8080"),
		Environment:         getenv("PASSWD_ENV", "development"),
		JWTSecret:           getSecret("PASSWD_JWT_SECRET", "dev-only-insecure-secret-change-me"),
		DBPath:              getenv("PASSWD_DB", "data/passwd.db"),
		IdentifierPepper:    getSecret("PASSWD_IDENTIFIER_PEPPER", "dev-only-insecure-pepper-change-me"),
		AuthRateLimitPerMin: getenvInt("PASSWD_AUTH_RATELIMIT_PER_MIN", 60),
		AllowedOrigins:      allowedOrigins,
		WebAuthnRPID:        getenv("PASSWD_WEBAUTHN_RP_ID", "localhost"),
		WebAuthnRPName:      getenv("PASSWD_WEBAUTHN_RP_NAME", "passwd"),
		WebAuthnRPOrigins:   rpOrigins,
		TrustedProxies:      splitList(getenv("PASSWD_TRUSTED_PROXIES", "")),
	}
}

func (c Config) IsProduction() bool { return c.Environment == "production" }

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// getSecret resolves a secret from "<KEY>_FILE" (the file's trimmed contents)
// first, then "<KEY>" (the env value), else the fallback. The _FILE form is the
// standard way to inject Docker/Kubernetes secrets mounted as files, so the value
// never sits in the process environment or compose file.
func getSecret(key, fallback string) string {
	if path := os.Getenv(key + "_FILE"); path != "" {
		if b, err := os.ReadFile(path); err == nil {
			if s := strings.TrimSpace(string(b)); s != "" {
				return s
			}
		}
	}
	return getenv(key, fallback)
}

func getenvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

// splitList parses a comma-separated env value into a trimmed, non-empty slice.
func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}
