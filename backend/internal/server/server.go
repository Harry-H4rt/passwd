// Package server is the HTTP transport layer: routing, middleware, and handlers.
package server

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/passwd-app/server/internal/config"
	"github.com/passwd-app/server/internal/storage"
	"github.com/passwd-app/server/internal/vault"
)

type Server struct {
	cfg     config.Config
	store   storage.Store
	vault   *vault.Service
	logger  *slog.Logger
	limiter *rateLimiter
	lockout *lockoutTracker
}

func New(cfg config.Config, store storage.Store, logger *slog.Logger) *Server {
	rate := cfg.AuthRateLimitPerMin
	if rate <= 0 {
		rate = 60
	}
	return &Server{
		cfg:     cfg,
		store:   store,
		vault:   vault.New(store),
		logger:  logger,
		limiter: newRateLimiter(rate, time.Minute),
		lockout: newLockoutTracker(5, 15*time.Minute), // 5 fails -> 15 min lock
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

	// Vault sync — requires a valid access token.
	mux.Handle("GET /api/sync", s.requireAuth(http.HandlerFunc(s.handleSync)))
	mux.Handle("POST /api/ciphers", s.requireAuth(http.HandlerFunc(s.handleCreateCipher)))
	mux.Handle("PUT /api/ciphers/{id}", s.requireAuth(http.HandlerFunc(s.handleUpdateCipher)))
	mux.Handle("DELETE /api/ciphers/{id}", s.requireAuth(http.HandlerFunc(s.handleDeleteCipher)))

	return s.withMiddleware(mux)
}

func (s *Server) withMiddleware(next http.Handler) http.Handler {
	return s.recoverer(s.requestLogger(s.securityHeaders(next)))
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
