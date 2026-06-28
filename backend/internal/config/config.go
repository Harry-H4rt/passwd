// Package config loads runtime configuration from the environment.
package config

import "os"

type Config struct {
	Addr        string // listen address, e.g. ":8080"
	Environment string // "development" | "production"
	JWTSecret   string // signing secret for access tokens (Phase 2)
}

func Load() Config {
	return Config{
		Addr:        getenv("PASSWD_ADDR", ":8080"),
		Environment: getenv("PASSWD_ENV", "development"),
		JWTSecret:   getenv("PASSWD_JWT_SECRET", "dev-only-insecure-secret-change-me"),
	}
}

func (c Config) IsProduction() bool { return c.Environment == "production" }

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
