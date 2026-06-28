package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/passwd-app/server/internal/auth"
	"github.com/passwd-app/server/internal/storage"
)

// --- Health -----------------------------------------------------------------

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// --- Prelogin ---------------------------------------------------------------

type preloginRequest struct {
	Email string `json:"email"`
}

type preloginResponse struct {
	KDF storage.KDFParams `json:"kdf"`
}

// handlePrelogin returns the KDF parameters the client must use to derive the
// master key. For unknown emails it returns defaults rather than 404, so the
// endpoint does not reveal whether an account exists.
func (s *Server) handlePrelogin(w http.ResponseWriter, r *http.Request) {
	var req preloginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	kdf := auth.DefaultKDF
	if u, err := s.store.GetUserByEmail(r.Context(), req.Email); err == nil {
		kdf = u.KDF
	}
	writeJSON(w, http.StatusOK, preloginResponse{KDF: kdf})
}

// --- Register ---------------------------------------------------------------

type registerRequest struct {
	Email string            `json:"email"`
	KDF   storage.KDFParams `json:"kdf"`
	// MasterPasswordHash is the client-derived auth credential (NOT the password).
	MasterPasswordHash string `json:"masterPasswordHash"`
	// ProtectedUserKey is the User Key wrapped by the stretched master key.
	ProtectedUserKey string `json:"protectedUserKey"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Email == "" || req.MasterPasswordHash == "" || req.ProtectedUserKey == "" {
		writeError(w, http.StatusBadRequest, "email, masterPasswordHash and protectedUserKey are required")
		return
	}

	// SECURITY TODO(Phase 2): hash the verifier with Argon2id + random salt.
	// Storing the client-provided hash verbatim is a PLACEHOLDER for Phase 0 and
	// is NOT production-safe.
	s.logger.Warn("register: storing UNHASHED master password verifier (Phase 0 placeholder)")

	now := time.Now().UTC()
	u := storage.User{
		ID:                     newID(),
		Email:                  req.Email,
		KDF:                    req.KDF,
		MasterPasswordVerifier: "PLACEHOLDER:" + req.MasterPasswordHash,
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
	writeJSON(w, http.StatusCreated, map[string]string{"id": u.ID})
}

// --- Login (Phase 2) --------------------------------------------------------

func (s *Server) handleLogin(w http.ResponseWriter, _ *http.Request) {
	// Phase 2: verify Argon2id(masterPasswordHash) against the stored verifier,
	// then issue JWT access + refresh tokens and return the ProtectedUserKey.
	writeError(w, http.StatusNotImplemented, "login not implemented (see docs/ROADMAP.md Phase 2)")
}

func (s *Server) notImplemented(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusNotImplemented, "not implemented yet (see docs/ROADMAP.md)")
}

// --- helpers ----------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)) // 1 MiB cap
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
