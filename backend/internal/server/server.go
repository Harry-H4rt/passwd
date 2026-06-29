// Package server is the HTTP transport layer: routing, middleware, and handlers.
package server

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/passwd-app/server/internal/config"
	"github.com/passwd-app/server/internal/storage"
	"github.com/passwd-app/server/internal/vault"
)

type Server struct {
	cfg            config.Config
	store          storage.Store
	vault          *vault.Service
	logger         *slog.Logger
	limiter        *rateLimiter
	lockout        *lockoutTracker
	allowedOrigins map[string]bool
	// webAuthn is the passkey relying-party engine. Nil if RP config is invalid, in
	// which case the passkey endpoints return 503 (TOTP and password login are
	// unaffected).
	webAuthn  *webauthn.WebAuthn
	waPending *challengeStore
}

func New(cfg config.Config, store storage.Store, logger *slog.Logger) *Server {
	rate := cfg.AuthRateLimitPerMin
	if rate <= 0 {
		rate = 60
	}
	allowed := make(map[string]bool, len(cfg.AllowedOrigins))
	for _, o := range cfg.AllowedOrigins {
		allowed[o] = true
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.WebAuthnRPID,
		RPDisplayName: cfg.WebAuthnRPName,
		RPOrigins:     cfg.WebAuthnRPOrigins,
	})
	if err != nil {
		// Don't kill the whole server over passkey misconfig; just disable passkeys.
		logger.Error("webauthn disabled: invalid RP config", "err", err)
		wa = nil
	}
	return &Server{
		cfg:            cfg,
		store:          store,
		vault:          vault.New(store),
		logger:         logger,
		limiter:        newRateLimiter(rate, time.Minute),
		lockout:        newLockoutTracker(5, 15*time.Minute), // 5 fails -> 15 min lock
		allowedOrigins: allowed,
		webAuthn:       wa,
		waPending:      newChallengeStore(2 * time.Minute),
	}
}

// Routes builds the handler tree using Go 1.22's method+path mux.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.handleHealth)

	// Account / auth — rate limited per IP.
	mux.Handle("POST /api/accounts/prelogin", s.rateLimit(http.HandlerFunc(s.handlePrelogin)))
	mux.Handle("POST /api/accounts/register", s.rateLimit(http.HandlerFunc(s.handleRegister)))
	mux.Handle("POST /api/auth/login", s.rateLimit(http.HandlerFunc(s.handleLogin)))
	mux.Handle("POST /api/auth/refresh", s.rateLimit(http.HandlerFunc(s.handleRefresh)))

	// Two-factor (TOTP) — requires a valid access token.
	mux.Handle("GET /api/2fa", s.requireAuth(http.HandlerFunc(s.handleTOTPStatus)))
	mux.Handle("POST /api/2fa/setup", s.requireAuth(http.HandlerFunc(s.handleTOTPSetup)))
	mux.Handle("POST /api/2fa/enable", s.requireAuth(http.HandlerFunc(s.handleTOTPEnable)))
	mux.Handle("POST /api/2fa/disable", s.requireAuth(http.HandlerFunc(s.handleTOTPDisable)))

	// Passkey (WebAuthn) enrollment — requires a valid access token.
	mux.Handle("GET /api/2fa/webauthn/credentials", s.requireAuth(http.HandlerFunc(s.handleWebAuthnList)))
	mux.Handle("DELETE /api/2fa/webauthn/credentials/{id}", s.requireAuth(http.HandlerFunc(s.handleWebAuthnDelete)))
	mux.Handle("POST /api/2fa/webauthn/register/begin", s.requireAuth(http.HandlerFunc(s.handleWebAuthnRegisterBegin)))
	mux.Handle("POST /api/2fa/webauthn/register/finish", s.requireAuth(http.HandlerFunc(s.handleWebAuthnRegisterFinish)))

	// Passkey (WebAuthn) login assertion — password is re-verified on each call, so
	// these are rate limited like the other auth endpoints (no access token yet).
	mux.Handle("POST /api/auth/webauthn/begin", s.rateLimit(http.HandlerFunc(s.handleWebAuthnLoginBegin)))
	mux.Handle("POST /api/auth/webauthn/finish", s.rateLimit(http.HandlerFunc(s.handleWebAuthnLoginFinish)))

	// Vault sync — requires a valid access token.
	mux.Handle("GET /api/sync", s.requireAuth(http.HandlerFunc(s.handleSync)))
	mux.Handle("POST /api/ciphers", s.requireAuth(http.HandlerFunc(s.handleCreateCipher)))
	mux.Handle("PUT /api/ciphers/{id}", s.requireAuth(http.HandlerFunc(s.handleUpdateCipher)))
	mux.Handle("DELETE /api/ciphers/{id}", s.requireAuth(http.HandlerFunc(s.handleDeleteCipher)))

	return s.withMiddleware(mux)
}

func (s *Server) withMiddleware(next http.Handler) http.Handler {
	return s.recoverer(s.requestLogger(s.cors(s.securityHeaders(next))))
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.logger.Error("panic recovered", "err", rec, "path", r.URL.Path)
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		// Deliberately logs no identifier/PII — only method, path, status, timing.
		s.logger.Info("request",
			"method", r.Method, "path", r.URL.Path,
			"status", sw.status, "dur", time.Since(start).String())
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		// This service only ever returns JSON; lock the page down entirely.
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		if s.cfg.IsProduction() {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}
