package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/passwd-app/server/internal/auth"
	"github.com/passwd-app/server/internal/storage"
)

// 1:1 item sharing. The server resolves recipients by their blinded identifier and
// stores opaque share payloads — an item key encrypted to the recipient's public
// key, plus the item ciphertext. It can read neither, and never learns the
// recipient's plaintext identifier.

// handleLookupPublicKey returns a user's sharing public key by identifier, so a
// sender can encrypt to it. This is a deliberate (rate-limited, auth-only)
// existence check: sharing requires knowing the recipient.
func (s *Server) handleLookupPublicKey(w http.ResponseWriter, r *http.Request) {
	if _, ok := userIDFrom(r.Context()); !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	identifier := r.URL.Query().Get("identifier")
	if identifier == "" {
		writeError(w, http.StatusBadRequest, "identifier is required")
		return
	}
	idHash := auth.BlindIdentifier(s.cfg.IdentifierPepper, identifier)
	u, err := s.store.GetUserByIdentifierHash(r.Context(), idHash)
	if err != nil || u.PublicKey == "" {
		writeError(w, http.StatusNotFound, "no such user, or they can't receive shares")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"publicKey": u.PublicKey})
}

type createShareRequest struct {
	RecipientIdentifier string `json:"recipientIdentifier"`
	WrappedKey          string `json:"wrappedKey"`
	Data                string `json:"data"`
}

func (s *Server) handleCreateShare(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req createShareRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.RecipientIdentifier == "" || req.WrappedKey == "" || req.Data == "" {
		writeError(w, http.StatusBadRequest, "recipientIdentifier, wrappedKey and data are required")
		return
	}
	idHash := auth.BlindIdentifier(s.cfg.IdentifierPepper, req.RecipientIdentifier)
	recipient, err := s.store.GetUserByIdentifierHash(r.Context(), idHash)
	if err != nil || recipient.PublicKey == "" {
		writeError(w, http.StatusNotFound, "no such recipient, or they can't receive shares")
		return
	}
	sh := storage.Share{
		ID:              newID(),
		OwnerUserID:     userID,
		RecipientUserID: recipient.ID,
		WrappedKey:      req.WrappedKey,
		Data:            req.Data,
		CreatedAt:       time.Now().UTC(),
	}
	if err := s.store.CreateShare(r.Context(), sh); err != nil {
		s.logger.Error("create share", "err", err)
		writeError(w, http.StatusInternalServerError, "could not share item")
		return
	}
	s.audit(r.Context(), userID, evtShareCreate, "")
	writeJSON(w, http.StatusCreated, map[string]string{"id": sh.ID})
}

type shareDTO struct {
	ID         string `json:"id"`
	WrappedKey string `json:"wrappedKey"`
	Data       string `json:"data"`
	CreatedAt  string `json:"createdAt"`
}

// handleListShares returns the shares addressed to the caller (incoming).
func (s *Server) handleListShares(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	shares, err := s.store.ListSharesForRecipient(r.Context(), userID)
	if err != nil {
		s.logger.Error("list shares", "err", err)
		writeError(w, http.StatusInternalServerError, "could not load shares")
		return
	}
	out := make([]shareDTO, len(shares))
	for i, sh := range shares {
		out[i] = shareDTO{ID: sh.ID, WrappedKey: sh.WrappedKey, Data: sh.Data, CreatedAt: sh.CreatedAt.Format(time.RFC3339)}
	}
	writeJSON(w, http.StatusOK, map[string]any{"shares": out})
}

func (s *Server) handleDeleteShare(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err := s.store.DeleteShare(r.Context(), userID, r.PathValue("id")); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "share not found")
			return
		}
		s.logger.Error("delete share", "err", err)
		writeError(w, http.StatusInternalServerError, "could not delete share")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
