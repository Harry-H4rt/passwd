package server

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/passwd-app/server/internal/auth"
)

type ctxKey int

const ctxUserID ctxKey = iota

// --- access-token auth ------------------------------------------------------

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, prefix) {
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		userID, err := auth.ParseAccessToken(strings.TrimPrefix(h, prefix), s.cfg.JWTSecret)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}
		ctx := context.WithValue(r.Context(), ctxUserID, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func userIDFrom(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(ctxUserID).(string)
	return id, ok && id != ""
}

// --- IP rate limiting (fixed window, in-memory/ephemeral) -------------------

type rateLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	counters map[string]*rlEntry
}

type rlEntry struct {
	count   int
	resetAt time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, counters: map[string]*rlEntry{}}
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	e, ok := rl.counters[key]
	if !ok || now.After(e.resetAt) {
		rl.counters[key] = &rlEntry{count: 1, resetAt: now.Add(rl.window)}
		return true
	}
	if e.count >= rl.limit {
		return false
	}
	e.count++
	return true
}

func (s *Server) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.limiter.allow(clientIP(r)) {
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded; slow down")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// --- per-account login lockout (in-memory/ephemeral) ------------------------

type lockoutTracker struct {
	mu       sync.Mutex
	maxFails int
	lockFor  time.Duration
	entries  map[string]*lockEntry
}

type lockEntry struct {
	fails      int
	lockedTill time.Time
}

func newLockoutTracker(maxFails int, lockFor time.Duration) *lockoutTracker {
	return &lockoutTracker{maxFails: maxFails, lockFor: lockFor, entries: map[string]*lockEntry{}}
}

// locked reports whether key is currently locked out.
func (lt *lockoutTracker) locked(key string) bool {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	e, ok := lt.entries[key]
	return ok && time.Now().Before(e.lockedTill)
}

func (lt *lockoutTracker) recordFailure(key string) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	e, ok := lt.entries[key]
	if !ok {
		e = &lockEntry{}
		lt.entries[key] = e
	}
	e.fails++
	if e.fails >= lt.maxFails {
		e.lockedTill = time.Now().Add(lt.lockFor)
		e.fails = 0
	}
}

func (lt *lockoutTracker) reset(key string) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	delete(lt.entries, key)
}
