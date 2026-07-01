package server

import (
	"net/http"
	"time"
)

// A session is an active refresh-token family (one per signed-in device). We
// expose only timestamps — never the token hash — so the list can't be used to
// reconstruct a token.
type sessionDTO struct {
	CreatedAt string `json:"createdAt"`
	ExpiresAt string `json:"expiresAt"`
}

// handleListSessions returns the authenticated user's active sessions, newest
// first, so they can see how many devices are signed in.
func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	tokens, err := s.store.ListRefreshTokensForUser(r.Context(), userID)
	if err != nil {
		s.logger.Error("list sessions", "err", err)
		writeError(w, http.StatusInternalServerError, "could not load sessions")
		return
	}
	out := make([]sessionDTO, len(tokens))
	for i, t := range tokens {
		out[i] = sessionDTO{
			CreatedAt: t.CreatedAt.Format(time.RFC3339),
			ExpiresAt: t.ExpiresAt.Format(time.RFC3339),
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

// handleLogoutAll signs the user out of every device by revoking all refresh
// tokens. Access tokens are stateless and lapse within their short TTL, so no
// device can renew afterward. Used from the vault's "sign out everywhere".
func (s *Server) handleLogoutAll(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err := s.store.DeleteRefreshTokensForUser(r.Context(), userID); err != nil {
		s.logger.Error("logout all", "err", err)
		writeError(w, http.StatusInternalServerError, "could not sign out sessions")
		return
	}
	s.audit(r.Context(), userID, evtSessionRevokeAll, "")
	w.WriteHeader(http.StatusNoContent)
}
