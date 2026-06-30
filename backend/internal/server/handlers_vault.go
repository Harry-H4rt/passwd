package server

import (
	"errors"
	"net/http"

	"github.com/passwd-app/server/internal/storage"
	"github.com/passwd-app/server/internal/vault"
)

type cipherRequest struct {
	Data string `json:"data"` // EncString ciphertext
}

type syncResponse struct {
	Ciphers []vault.Item `json:"ciphers"`
}

func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	items, err := s.vault.List(r.Context(), userID)
	if err != nil {
		s.logger.Error("list ciphers", "err", err)
		writeError(w, http.StatusInternalServerError, "sync failed")
		return
	}
	writeJSON(w, http.StatusOK, syncResponse{Ciphers: items})
}

func (s *Server) handleCreateCipher(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req cipherRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Data == "" {
		writeError(w, http.StatusBadRequest, "data is required")
		return
	}
	item, err := s.vault.Create(r.Context(), userID, req.Data)
	if err != nil {
		s.logger.Error("create cipher", "err", err)
		writeError(w, http.StatusInternalServerError, "could not create item")
		return
	}
	s.audit(r.Context(), userID, evtCipherCreate, item.ID)
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) handleUpdateCipher(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := r.PathValue("id")
	var req cipherRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Data == "" {
		writeError(w, http.StatusBadRequest, "data is required")
		return
	}
	item, err := s.vault.Update(r.Context(), userID, id, req.Data)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "item not found")
			return
		}
		s.logger.Error("update cipher", "err", err)
		writeError(w, http.StatusInternalServerError, "could not update item")
		return
	}
	s.audit(r.Context(), userID, evtCipherUpdate, item.ID)
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleDeleteCipher(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := r.PathValue("id")
	if err := s.vault.Delete(r.Context(), userID, id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "item not found")
			return
		}
		s.logger.Error("delete cipher", "err", err)
		writeError(w, http.StatusInternalServerError, "could not delete item")
		return
	}
	s.audit(r.Context(), userID, evtCipherDelete, id)
	w.WriteHeader(http.StatusNoContent)
}
