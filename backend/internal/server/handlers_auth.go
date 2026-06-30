package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/passwd-app/server/internal/auth"
	"github.com/passwd-app/server/internal/storage"
)

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// --- Prelogin ---------------------------------------------------------------

type preloginRequest struct {
	Identifier string `json:"identifier"`
}

type preloginResponse struct {
	KDF storage.KDFParams `json:"kdf"`
}

// handlePrelogin returns the KDF parameters the client must use to derive the
// master key. Unknown identifiers get defaults (no account-existence oracle).
func (s *Server) handlePrelogin(w http.ResponseWriter, r *http.Request) {
	var req preloginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	kdf := auth.DefaultKDF
	idHash := auth.BlindIdentifier(s.cfg.IdentifierPepper, req.Identifier)
	if u, err := s.store.GetUserByIdentifierHash(r.Context(), idHash); err == nil {
		kdf = u.KDF
	}
	writeJSON(w, http.StatusOK, preloginResponse{KDF: kdf})
}

// --- Register ---------------------------------------------------------------

type registerRequest struct {
	Identifier         string            `json:"identifier"`
	KDF                storage.KDFParams `json:"kdf"`
	MasterPasswordHash string            `json:"masterPasswordHash"`
	ProtectedUserKey   string            `json:"protectedUserKey"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Identifier == "" || req.MasterPasswordHash == "" || req.ProtectedUserKey == "" {
		writeError(w, http.StatusBadRequest, "identifier, masterPasswordHash and protectedUserKey are required")
		return
	}
	if req.KDF.Type == "" {
		req.KDF = auth.DefaultKDF
	}

	verifier, err := auth.HashVerifier(req.MasterPasswordHash)
	if err != nil {
		s.logger.Error("hash verifier", "err", err)
		writeError(w, http.StatusInternalServerError, "could not create account")
		return
	}

	now := time.Now().UTC()
	u := storage.User{
		ID:                     newID(),
		IdentifierHash:         auth.BlindIdentifier(s.cfg.IdentifierPepper, req.Identifier),
		KDF:                    req.KDF,
		MasterPasswordVerifier: verifier,
		ProtectedUserKey:       req.ProtectedUserKey,
		CreatedAt:              now,
		UpdatedAt:              now,
	}
	if err := s.store.CreateUser(r.Context(), u); err != nil {
		if errors.Is(err, storage.ErrConflict) {
			writeError(w, http.StatusConflict, "account already exists")
			return
		}
		s.logger.Error("create user", "err", err)
		writeError(w, http.StatusInternalServerError, "could not create account")
		return
	}
	s.audit(r.Context(), u.ID, evtRegister, "")
	writeJSON(w, http.StatusCreated, map[string]string{"id": u.ID})
}

// --- Login ------------------------------------------------------------------

type loginRequest struct {
	Identifier         string `json:"identifier"`
	MasterPasswordHash string `json:"masterPasswordHash"`
	TOTPCode           string `json:"totpCode"`
}

type loginResponse struct {
	AccessToken      string            `json:"accessToken"`
	RefreshToken     string            `json:"refreshToken"`
	ProtectedUserKey string            `json:"protectedUserKey"`
	KDF              storage.KDFParams `json:"kdf"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	idHash := auth.BlindIdentifier(s.cfg.IdentifierPepper, req.Identifier)

	if s.lockout.locked(idHash) {
		writeError(w, http.StatusTooManyRequests, "too many attempts; try again later")
		return
	}

	u, err := s.store.GetUserByIdentifierHash(r.Context(), idHash)
	accountExists := err == nil
	if err == nil {
		var ok bool
		ok, err = auth.VerifyVerifier(u.MasterPasswordVerifier, req.MasterPasswordHash)
		if err == nil && ok {
			// Password correct — enforce the second factor if enrolled. TOTP and
			// passkeys may coexist; the client picks one. TOTP completes inline (the
			// client retries this call with a code); passkeys complete via the
			// /api/auth/webauthn/{begin,finish} endpoints.
			hasPasskey := false
			if n, cerr := s.store.CountWebAuthnCredentials(r.Context(), u.ID); cerr == nil {
				hasPasskey = n > 0
			}
			if u.TOTPEnabled || hasPasskey {
				if req.TOTPCode == "" {
					methods := make([]string, 0, 2)
					if hasPasskey {
						methods = append(methods, "webauthn")
					}
					if u.TOTPEnabled {
						methods = append(methods, "totp")
					}
					writeJSON(w, http.StatusUnauthorized, map[string]any{
						"error":             "two-factor authentication required",
						"twoFactorRequired": true,
						"methods":           methods,
					})
					return
				}
				// A code was supplied: complete the TOTP path (single-use, no replay).
				if !u.TOTPEnabled || !s.verifyLoginTOTP(r.Context(), u, req.TOTPCode) {
					s.lockout.recordFailure(idHash)
					s.audit(r.Context(), u.ID, evtLoginFailure, "second factor")
					writeError(w, http.StatusUnauthorized, "invalid credentials")
					return
				}
			}
			tokens, terr := s.issueTokens(r, u.ID)
			if terr != nil {
				s.logger.Error("issue tokens", "err", terr)
				writeError(w, http.StatusInternalServerError, "login failed")
				return
			}
			s.lockout.reset(idHash)
			s.audit(r.Context(), u.ID, evtLoginSuccess, "")
			writeJSON(w, http.StatusOK, loginResponse{
				AccessToken:      tokens.access,
				RefreshToken:     tokens.refresh,
				ProtectedUserKey: u.ProtectedUserKey,
				KDF:              u.KDF,
			})
			return
		}
	} else {
		// Account not found: run a dummy Argon2id verification so timing matches the
		// wrong-password path and does not reveal whether the account exists.
		auth.DummyVerify(req.MasterPasswordHash)
	}

	// Wrong identifier or wrong password — same generic response either way. Only
	// record a failure event for a known account (an unknown identifier is not
	// attributable and must not create an audit entry).
	s.lockout.recordFailure(idHash)
	if accountExists {
		s.audit(r.Context(), u.ID, evtLoginFailure, "password")
	}
	writeError(w, http.StatusUnauthorized, "invalid credentials")
}

// --- Refresh ----------------------------------------------------------------

type refreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

type refreshResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "refreshToken is required")
		return
	}
	hash := auth.HashRefreshToken(req.RefreshToken)
	rt, err := s.store.GetRefreshToken(r.Context(), hash)
	if err != nil || time.Now().After(rt.ExpiresAt) {
		if err == nil {
			_ = s.store.DeleteRefreshToken(r.Context(), hash) // expired: clean up
		}
		writeError(w, http.StatusUnauthorized, "invalid or expired refresh token")
		return
	}

	// Reuse detection: a token is kept (marked used) after rotation. Presenting an
	// already-used token means it was replayed — likely stolen — so revoke the whole
	// session family for that user and refuse.
	if rt.Used {
		s.logger.Warn("refresh token reuse detected; revoking sessions", "user", rt.UserID)
		_ = s.store.DeleteRefreshTokensForUser(r.Context(), rt.UserID)
		s.audit(r.Context(), rt.UserID, evtTokenReuse, "")
		writeError(w, http.StatusUnauthorized, "invalid or expired refresh token")
		return
	}

	// Rotate: mark the presented token used (retained for reuse detection), issue a fresh pair.
	_ = s.store.MarkRefreshTokenUsed(r.Context(), hash)
	tokens, err := s.issueTokens(r, rt.UserID)
	if err != nil {
		s.logger.Error("issue tokens", "err", err)
		writeError(w, http.StatusInternalServerError, "refresh failed")
		return
	}
	writeJSON(w, http.StatusOK, refreshResponse{AccessToken: tokens.access, RefreshToken: tokens.refresh})
}

// --- token helper -----------------------------------------------------------

type tokenPair struct{ access, refresh string }

func (s *Server) issueTokens(r *http.Request, userID string) (tokenPair, error) {
	access, err := auth.IssueAccessToken(userID, s.cfg.JWTSecret, auth.AccessTokenTTL)
	if err != nil {
		return tokenPair{}, err
	}
	refresh, refreshHash, err := auth.GenerateRefreshToken()
	if err != nil {
		return tokenPair{}, err
	}
	now := time.Now().UTC()
	if err := s.store.CreateRefreshToken(r.Context(), storage.RefreshToken{
		TokenHash: refreshHash,
		UserID:    userID,
		ExpiresAt: now.Add(auth.RefreshTokenTTL),
		CreatedAt: now,
	}); err != nil {
		return tokenPair{}, err
	}
	return tokenPair{access: access, refresh: refresh}, nil
}
