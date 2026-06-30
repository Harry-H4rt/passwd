package server

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/passwd-app/server/internal/auth"
	"github.com/passwd-app/server/internal/storage"
)

// Account recovery: a user-controlled way back into the vault after a forgotten
// master password, with no server-side reset. While unlocked, the client wraps
// the SAME User Key under a key derived from a recovery code and uploads that
// blob plus a recovery verifier (Argon2id of a recovery auth hash). To recover,
// the client fetches the blob, unwraps the User Key with the code, picks a new
// master password, and proves possession of the code with the auth hash; the
// server then swaps in the new master-password verifier + re-wrapped User Key.
// The server never learns the recovery code, the User Key, or the new password,
// and cannot perform recovery on its own. See docs/CRYPTO.md.

// --- Status / enable / disable (authenticated) ------------------------------

func (s *Server) handleRecoveryStatus(w http.ResponseWriter, r *http.Request) {
	userID, _ := userIDFrom(r.Context())
	u, err := s.store.GetUserByID(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": u.RecoveryVerifier != ""})
}

type recoveryEnableRequest struct {
	RecoveryProtectedUserKey string `json:"recoveryProtectedUserKey"`
	RecoveryAuthHash         string `json:"recoveryAuthHash"`
}

func (s *Server) handleRecoveryEnable(w http.ResponseWriter, r *http.Request) {
	userID, _ := userIDFrom(r.Context())
	var req recoveryEnableRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.RecoveryProtectedUserKey == "" || req.RecoveryAuthHash == "" {
		writeError(w, http.StatusBadRequest, "recoveryProtectedUserKey and recoveryAuthHash are required")
		return
	}
	verifier, err := auth.HashVerifier(req.RecoveryAuthHash)
	if err != nil {
		s.logger.Error("hash recovery verifier", "err", err)
		writeError(w, http.StatusInternalServerError, "could not enable recovery")
		return
	}
	if err := s.store.SetUserRecovery(r.Context(), userID, req.RecoveryProtectedUserKey, verifier); err != nil {
		s.logger.Error("set recovery", "err", err)
		writeError(w, http.StatusInternalServerError, "could not enable recovery")
		return
	}
	s.audit(r.Context(), userID, evtRecoveryEnable, "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRecoveryDisable(w http.ResponseWriter, r *http.Request) {
	userID, _ := userIDFrom(r.Context())
	if err := s.store.ClearUserRecovery(r.Context(), userID); err != nil {
		s.logger.Error("clear recovery", "err", err)
		writeError(w, http.StatusInternalServerError, "could not disable recovery")
		return
	}
	s.audit(r.Context(), userID, evtRecoveryDisable, "")
	w.WriteHeader(http.StatusNoContent)
}

// --- Recovery flow (unauthenticated, rate-limited) --------------------------

type recoveryChallengeRequest struct {
	Identifier string `json:"identifier"`
}

type recoveryChallengeResponse struct {
	RecoveryProtectedUserKey string            `json:"recoveryProtectedUserKey"`
	KDF                      storage.KDFParams `json:"kdf"`
}

// handleRecoveryChallenge returns the recovery-wrapped User Key for an identifier
// so the client can try to unwrap it with the recovery code. Unknown identifiers
// (or accounts without recovery enabled) get a random decoy blob and default KDF,
// so this is not an account-existence or recovery-enabled oracle: a wrong code
// and a nonexistent account both fail identically (AEAD failure on the client).
func (s *Server) handleRecoveryChallenge(w http.ResponseWriter, r *http.Request) {
	var req recoveryChallengeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	resp := recoveryChallengeResponse{RecoveryProtectedUserKey: decoyRecoveryBlob(), KDF: auth.DefaultKDF}
	idHash := auth.BlindIdentifier(s.cfg.IdentifierPepper, req.Identifier)
	if u, err := s.store.GetUserByIdentifierHash(r.Context(), idHash); err == nil && u.RecoveryVerifier != "" {
		resp.RecoveryProtectedUserKey = u.RecoveryProtectedUserKey
		resp.KDF = u.KDF
	}
	writeJSON(w, http.StatusOK, resp)
}

type recoveryCompleteRequest struct {
	Identifier         string            `json:"identifier"`
	RecoveryAuthHash   string            `json:"recoveryAuthHash"`
	MasterPasswordHash string            `json:"masterPasswordHash"`
	ProtectedUserKey   string            `json:"protectedUserKey"`
	KDF                storage.KDFParams `json:"kdf"`
}

// handleRecoveryComplete verifies possession of the recovery code (via its auth
// hash) and, if valid, rotates the account onto a new master password: the new
// verifier, the User Key re-wrapped under the new password, and KDF params. On
// success the user is logged in. Note this is an account-level escape hatch that
// bypasses any TOTP/passkey second factor, so the recovery code must be guarded
// as carefully as the master password (documented in docs/CRYPTO.md).
func (s *Server) handleRecoveryComplete(w http.ResponseWriter, r *http.Request) {
	var req recoveryCompleteRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.RecoveryAuthHash == "" || req.MasterPasswordHash == "" || req.ProtectedUserKey == "" {
		writeError(w, http.StatusBadRequest, "recoveryAuthHash, masterPasswordHash and protectedUserKey are required")
		return
	}
	idHash := auth.BlindIdentifier(s.cfg.IdentifierPepper, req.Identifier)
	if s.lockout.locked(idHash) {
		writeError(w, http.StatusTooManyRequests, "too many attempts; try again later")
		return
	}

	u, err := s.store.GetUserByIdentifierHash(r.Context(), idHash)
	if err == nil && u.RecoveryVerifier != "" {
		ok, verr := auth.VerifyVerifier(u.RecoveryVerifier, req.RecoveryAuthHash)
		if verr == nil && ok {
			kdf := req.KDF
			if kdf.Type == "" {
				kdf = u.KDF
			}
			verifier, herr := auth.HashVerifier(req.MasterPasswordHash)
			if herr != nil {
				s.logger.Error("hash verifier", "err", herr)
				writeError(w, http.StatusInternalServerError, "recovery failed")
				return
			}
			if rerr := s.store.RotateMasterPassword(r.Context(), u.ID, verifier, req.ProtectedUserKey, kdf); rerr != nil {
				s.logger.Error("rotate master password", "err", rerr)
				writeError(w, http.StatusInternalServerError, "recovery failed")
				return
			}
			// Recovery often follows a suspected compromise: revoke every existing
			// session so a stolen refresh token cannot outlive the password reset.
			if derr := s.store.DeleteRefreshTokensForUser(r.Context(), u.ID); derr != nil {
				s.logger.Error("revoke sessions on recovery", "err", derr)
			}
			s.audit(r.Context(), u.ID, evtRecoveryComplete, "")
			tokens, terr := s.issueTokens(r, u.ID)
			if terr != nil {
				s.logger.Error("issue tokens", "err", terr)
				writeError(w, http.StatusInternalServerError, "recovery failed")
				return
			}
			s.lockout.reset(idHash)
			writeJSON(w, http.StatusOK, loginResponse{
				AccessToken:      tokens.access,
				RefreshToken:     tokens.refresh,
				ProtectedUserKey: req.ProtectedUserKey,
				KDF:              kdf,
			})
			return
		}
	} else {
		// No account or recovery not enabled: run a dummy verification so timing
		// does not reveal which accounts exist or have recovery configured.
		auth.DummyVerify(req.RecoveryAuthHash)
	}

	// Unknown identifier, recovery not enabled, or wrong code — same generic reply.
	s.lockout.recordFailure(idHash)
	writeError(w, http.StatusUnauthorized, "invalid recovery code")
}

// decoyRecoveryBlob returns a random, well-formed EncString shaped like a real
// recovery-wrapped User Key (12-byte nonce, 64-byte key + 16-byte GCM tag) so a
// challenge for a nonexistent/opted-out account is indistinguishable from a real
// one until the client fails to decrypt it.
func decoyRecoveryBlob() string {
	nonce := make([]byte, 12)
	data := make([]byte, 80)
	_, _ = rand.Read(nonce)
	_, _ = rand.Read(data)
	return fmt.Sprintf("1.%s|%s",
		base64.StdEncoding.EncodeToString(nonce),
		base64.StdEncoding.EncodeToString(data))
}
