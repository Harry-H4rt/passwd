package server

import (
	"context"
	"net/http"

	"github.com/passwd-app/server/internal/auth"
	"github.com/passwd-app/server/internal/storage"
)

// totpSecret decrypts a stored (at-rest encrypted) TOTP secret.
func (s *Server) totpSecret(stored string) (string, bool) {
	pt, err := auth.DecryptSecret(s.totpKey, stored)
	if err != nil {
		return "", false
	}
	return pt, true
}

// verifyLoginTOTP verifies a login TOTP code and enforces single use: the code's
// time-step must be strictly greater than the last one consumed, so a code cannot
// be replayed within its validity window. Used by the login path only (enrollment
// and disable are already access-token-gated).
func (s *Server) verifyLoginTOTP(ctx context.Context, u storage.User, code string) bool {
	secret, ok := s.totpSecret(u.TOTPSecret)
	if !ok {
		return false
	}
	counter, ok := auth.VerifyTOTPAt(secret, code)
	if !ok || counter <= u.TOTPLastCounter {
		return false
	}
	if err := s.store.SetUserTOTPCounter(ctx, u.ID, counter); err != nil {
		s.logger.Error("totp counter", "err", err)
		return false
	}
	return true
}

// Two-factor (TOTP) endpoints, all behind requireAuth. Enrollment is two-step:
// setup (generate + store a not-yet-active secret, return it so the client can
// show a QR/otpauth) then enable (confirm with a valid code).

type totpCodeRequest struct {
	Code string `json:"code"`
}

func (s *Server) handleTOTPStatus(w http.ResponseWriter, r *http.Request) {
	userID, _ := userIDFrom(r.Context())
	u, err := s.store.GetUserByID(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": u.TOTPEnabled})
}

func (s *Server) handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	userID, _ := userIDFrom(r.Context())
	u, err := s.store.GetUserByID(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if u.TOTPEnabled {
		writeError(w, http.StatusConflict, "two-factor is already enabled; disable it first")
		return
	}
	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		s.logger.Error("totp secret", "err", err)
		writeError(w, http.StatusInternalServerError, "could not start setup")
		return
	}
	// Store the secret encrypted at rest, disabled until the user confirms a code.
	enc, err := auth.EncryptSecret(s.totpKey, secret)
	if err != nil {
		s.logger.Error("totp seal", "err", err)
		writeError(w, http.StatusInternalServerError, "could not start setup")
		return
	}
	if err := s.store.SetUserTOTP(r.Context(), userID, enc, false); err != nil {
		s.logger.Error("totp store", "err", err)
		writeError(w, http.StatusInternalServerError, "could not start setup")
		return
	}
	// Return only the plaintext secret; the client builds the otpauth URI with the
	// user's identifier so it never reaches the server.
	writeJSON(w, http.StatusOK, map[string]string{"secret": secret})
}

func (s *Server) handleTOTPEnable(w http.ResponseWriter, r *http.Request) {
	userID, _ := userIDFrom(r.Context())
	var req totpCodeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	u, err := s.store.GetUserByID(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if u.TOTPSecret == "" {
		writeError(w, http.StatusBadRequest, "run setup first")
		return
	}
	secret, ok := s.totpSecret(u.TOTPSecret)
	if !ok || !auth.VerifyTOTP(secret, req.Code) {
		writeError(w, http.StatusBadRequest, "invalid code")
		return
	}
	if err := s.store.SetUserTOTP(r.Context(), userID, u.TOTPSecret, true); err != nil {
		s.logger.Error("totp enable", "err", err)
		writeError(w, http.StatusInternalServerError, "could not enable two-factor")
		return
	}
	s.audit(r.Context(), userID, evtTOTPEnable, "")
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": true})
}

func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	userID, _ := userIDFrom(r.Context())
	var req totpCodeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	u, err := s.store.GetUserByID(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if !u.TOTPEnabled {
		writeJSON(w, http.StatusOK, map[string]bool{"enabled": false})
		return
	}
	secret, ok := s.totpSecret(u.TOTPSecret)
	if !ok || !auth.VerifyTOTP(secret, req.Code) {
		writeError(w, http.StatusBadRequest, "invalid code")
		return
	}
	if err := s.store.SetUserTOTP(r.Context(), userID, "", false); err != nil {
		s.logger.Error("totp disable", "err", err)
		writeError(w, http.StatusInternalServerError, "could not disable two-factor")
		return
	}
	s.audit(r.Context(), userID, evtTOTPDisable, "")
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": false})
}
