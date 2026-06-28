package server

import (
	"net/http"

	"github.com/passwd-app/server/internal/auth"
)

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
	// Store the secret but leave it disabled until the user confirms a code.
	if err := s.store.SetUserTOTP(r.Context(), userID, secret, false); err != nil {
		s.logger.Error("totp store", "err", err)
		writeError(w, http.StatusInternalServerError, "could not start setup")
		return
	}
	// Return only the secret; the client builds the otpauth URI with the user's
	// identifier so it never reaches the server.
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
	if !auth.VerifyTOTP(u.TOTPSecret, req.Code) {
		writeError(w, http.StatusBadRequest, "invalid code")
		return
	}
	if err := s.store.SetUserTOTP(r.Context(), userID, u.TOTPSecret, true); err != nil {
		s.logger.Error("totp enable", "err", err)
		writeError(w, http.StatusInternalServerError, "could not enable two-factor")
		return
	}
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
	if !auth.VerifyTOTP(u.TOTPSecret, req.Code) {
		writeError(w, http.StatusBadRequest, "invalid code")
		return
	}
	if err := s.store.SetUserTOTP(r.Context(), userID, "", false); err != nil {
		s.logger.Error("totp disable", "err", err)
		writeError(w, http.StatusInternalServerError, "could not disable two-factor")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": false})
}
