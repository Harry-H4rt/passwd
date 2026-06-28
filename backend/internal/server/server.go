// Package server is the HTTP transport layer: routing, middleware, and handlers.
package server

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/passwd-app/server/internal/config"
	"github.com/passwd-app/server/internal/storage"
)

type Server struct {
	cfg    config.Config
	store  storage.Store
	logger *slog.Logger
}

func New(cfg config.Config, store storage.Store, logger *slog.Logger) *Server {
	return &Server{cfg: cfg, store: store, logger: logger}
}

// Routes builds the handler tree using Go 1.22's method+path mux (no router dep).
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.handleHealth)

	// Account / auth
	mux.HandleFunc("POST /api/accounts/prelogin", s.handlePrelogin)
	mux.HandleFunc("POST /api/accounts/register", s.handleRegister)
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/auth/refresh", s.notImplemented)

	// Vault sync (Phase 2: protect with auth middleware)
	mux.HandleFunc("GET /api/sync", s.notImplemented)
	mux.HandleFunc("POST /api/ciphers", s.notImplemented)
	mux.HandleFunc("PUT /api/ciphers/{id}", s.notImplemented)
	mux.HandleFunc("DELETE /api/ciphers/{id}", s.notImplemented)

	return s.withMiddleware(mux)
}

// withMiddleware wraps the mux with recovery, request logging, and security
// headers, applied outermost-first.
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
