package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/passwd-app/server/internal/auth"
	"github.com/passwd-app/server/internal/storage"
)

// Passkey (WebAuthn) endpoints. Passkeys are a *second factor* that coexists with
// TOTP — never passwordless. A WebAuthn assertion is signed over a server-issued
// challenge, so unlike TOTP these flows are two-step (begin -> finish) with the
// challenge held server-side in waPending between the two calls.
//
// Privacy: the relying-party user is the random account ID, with a generic name, so
// nothing the server hands the authenticator can identify the account holder.

// --- challenge store --------------------------------------------------------

// challengeStore holds webauthn.SessionData between a begin and finish call, keyed
// by an opaque single-use handle with a short TTL. In-memory/ephemeral, mirroring
// the rate limiter and lockout tracker — fine for the single-tenant deployment.
type challengeStore struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]challengeEntry
}

type challengeEntry struct {
	data    webauthn.SessionData
	userID  string
	expires time.Time
}

func newChallengeStore(ttl time.Duration) *challengeStore {
	return &challengeStore{ttl: ttl, m: make(map[string]challengeEntry)}
}

func (c *challengeStore) put(userID string, data webauthn.SessionData) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gc()
	c.m[id] = challengeEntry{data: data, userID: userID, expires: time.Now().Add(c.ttl)}
	return id
}

// take returns and removes the entry for id (single use). The bool is false if the
// handle is unknown or expired.
func (c *challengeStore) take(id string) (challengeEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[id]
	if ok {
		delete(c.m, id)
	}
	if !ok || time.Now().After(e.expires) {
		return challengeEntry{}, false
	}
	return e, true
}

func (c *challengeStore) gc() {
	now := time.Now()
	for k, e := range c.m {
		if now.After(e.expires) {
			delete(c.m, k)
		}
	}
}

// --- relying-party user -----------------------------------------------------

// webAuthnUser adapts an account to go-webauthn's User interface. The handle is the
// random account ID; the name is deliberately generic so server-generated options
// never carry the plaintext identifier.
type webAuthnUser struct {
	id          []byte
	credentials []webauthn.Credential
}

func (u *webAuthnUser) WebAuthnID() []byte                         { return u.id }
func (u *webAuthnUser) WebAuthnName() string                       { return "passwd user" }
func (u *webAuthnUser) WebAuthnDisplayName() string                { return "passwd user" }
func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// webAuthnUserFor loads a user's enrolled passkeys and wraps them for go-webauthn.
func (s *Server) webAuthnUserFor(ctx context.Context, userID string) (*webAuthnUser, []storage.WebAuthnCredential, error) {
	creds, err := s.store.ListWebAuthnCredentials(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	wcreds := make([]webauthn.Credential, 0, len(creds))
	for _, c := range creds {
		wcreds = append(wcreds, toWebAuthnCredential(c))
	}
	return &webAuthnUser{id: []byte(userID), credentials: wcreds}, creds, nil
}

func toWebAuthnCredential(c storage.WebAuthnCredential) webauthn.Credential {
	var transports []protocol.AuthenticatorTransport
	if c.Transports != "" {
		var ts []string
		if err := json.Unmarshal([]byte(c.Transports), &ts); err == nil {
			for _, t := range ts {
				transports = append(transports, protocol.AuthenticatorTransport(t))
			}
		}
	}
	return webauthn.Credential{
		ID:              c.CredentialID,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		Transport:       transports,
		Authenticator: webauthn.Authenticator{
			AAGUID:    c.AAGUID,
			SignCount: c.SignCount,
		},
	}
}

func fromWebAuthnCredential(userID, name string, wc *webauthn.Credential) storage.WebAuthnCredential {
	ts := make([]string, 0, len(wc.Transport))
	for _, t := range wc.Transport {
		ts = append(ts, string(t))
	}
	tj, _ := json.Marshal(ts)
	now := time.Now().UTC()
	return storage.WebAuthnCredential{
		ID:              newID(),
		UserID:          userID,
		CredentialID:    wc.ID,
		PublicKey:       wc.PublicKey,
		AttestationType: wc.AttestationType,
		Transports:      string(tj),
		AAGUID:          wc.Authenticator.AAGUID,
		SignCount:       wc.Authenticator.SignCount,
		Name:            name,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
}

// --- enrollment (behind requireAuth) ----------------------------------------

func (s *Server) handleWebAuthnList(w http.ResponseWriter, r *http.Request) {
	userID, _ := userIDFrom(r.Context())
	creds, err := s.store.ListWebAuthnCredentials(r.Context(), userID)
	if err != nil {
		s.logger.Error("webauthn list", "err", err)
		writeError(w, http.StatusInternalServerError, "could not list passkeys")
		return
	}
	type item struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		CreatedAt string `json:"createdAt"`
	}
	out := make([]item, 0, len(creds))
	for _, c := range creds {
		out = append(out, item{ID: c.ID, Name: c.Name, CreatedAt: c.CreatedAt.Format(time.RFC3339)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"credentials": out})
}

func (s *Server) handleWebAuthnDelete(w http.ResponseWriter, r *http.Request) {
	userID, _ := userIDFrom(r.Context())
	id := r.PathValue("id")
	if err := s.store.DeleteWebAuthnCredential(r.Context(), userID, id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "passkey not found")
			return
		}
		s.logger.Error("webauthn delete", "err", err)
		writeError(w, http.StatusInternalServerError, "could not delete passkey")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

func (s *Server) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if s.webAuthn == nil {
		writeError(w, http.StatusServiceUnavailable, "passkeys are not configured")
		return
	}
	userID, _ := userIDFrom(r.Context())
	waUser, _, err := s.webAuthnUserFor(r.Context(), userID)
	if err != nil {
		s.logger.Error("webauthn user", "err", err)
		writeError(w, http.StatusInternalServerError, "could not start passkey enrollment")
		return
	}
	// Exclude already-enrolled credentials so the same authenticator can't double-register.
	exclusions := make([]protocol.CredentialDescriptor, 0, len(waUser.credentials))
	for _, c := range waUser.credentials {
		exclusions = append(exclusions, c.Descriptor())
	}
	options, session, err := s.webAuthn.BeginRegistration(waUser, webauthn.WithExclusions(exclusions))
	if err != nil {
		s.logger.Error("webauthn begin registration", "err", err)
		writeError(w, http.StatusInternalServerError, "could not start passkey enrollment")
		return
	}
	sid := s.waPending.put(userID, *session)
	writeJSON(w, http.StatusOK, map[string]any{"sessionId": sid, "options": options})
}

func (s *Server) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if s.webAuthn == nil {
		writeError(w, http.StatusServiceUnavailable, "passkeys are not configured")
		return
	}
	userID, _ := userIDFrom(r.Context())
	var req struct {
		SessionID  string          `json:"sessionId"`
		Name       string          `json:"name"`
		Credential json.RawMessage `json:"credential"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	entry, ok := s.waPending.take(req.SessionID)
	if !ok || entry.userID != userID {
		writeError(w, http.StatusBadRequest, "passkey enrollment expired; start again")
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(req.Credential))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid passkey attestation")
		return
	}
	waUser, _, err := s.webAuthnUserFor(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not save passkey")
		return
	}
	cred, err := s.webAuthn.CreateCredential(waUser, entry.data, parsed)
	if err != nil {
		s.logger.Error("webauthn create credential", "err", err)
		writeError(w, http.StatusBadRequest, "could not verify passkey")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "Passkey"
	}
	rec := fromWebAuthnCredential(userID, name, cred)
	if err := s.store.CreateWebAuthnCredential(r.Context(), rec); err != nil {
		if errors.Is(err, storage.ErrConflict) {
			writeError(w, http.StatusConflict, "this passkey is already registered")
			return
		}
		s.logger.Error("webauthn store credential", "err", err)
		writeError(w, http.StatusInternalServerError, "could not save passkey")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": rec.ID, "name": rec.Name})
}

// --- login assertion (password re-verified, no token yet) -------------------

func (s *Server) handleWebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	if s.webAuthn == nil {
		writeError(w, http.StatusServiceUnavailable, "passkeys are not configured")
		return
	}
	var req struct {
		Identifier         string `json:"identifier"`
		MasterPasswordHash string `json:"masterPasswordHash"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	idHash := auth.BlindIdentifier(s.cfg.IdentifierPepper, req.Identifier)
	if s.lockout.locked(idHash) {
		writeError(w, http.StatusTooManyRequests, "too many attempts; try again later")
		return
	}
	u, err := s.store.GetUserByIdentifierHash(r.Context(), idHash)
	if err == nil {
		ok, verr := auth.VerifyVerifier(u.MasterPasswordVerifier, req.MasterPasswordHash)
		if verr == nil && ok {
			waUser, creds, uerr := s.webAuthnUserFor(r.Context(), u.ID)
			if uerr != nil {
				writeError(w, http.StatusInternalServerError, "could not start passkey login")
				return
			}
			if len(creds) == 0 {
				writeError(w, http.StatusBadRequest, "no passkeys enrolled")
				return
			}
			options, session, berr := s.webAuthn.BeginLogin(waUser)
			if berr != nil {
				s.logger.Error("webauthn begin login", "err", berr)
				writeError(w, http.StatusInternalServerError, "could not start passkey login")
				return
			}
			sid := s.waPending.put(u.ID, *session)
			writeJSON(w, http.StatusOK, map[string]any{"sessionId": sid, "options": options})
			return
		}
	}
	// Wrong identifier or password — generic response, counts toward lockout.
	s.lockout.recordFailure(idHash)
	writeError(w, http.StatusUnauthorized, "invalid credentials")
}

func (s *Server) handleWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	if s.webAuthn == nil {
		writeError(w, http.StatusServiceUnavailable, "passkeys are not configured")
		return
	}
	var req struct {
		Identifier         string          `json:"identifier"`
		MasterPasswordHash string          `json:"masterPasswordHash"`
		SessionID          string          `json:"sessionId"`
		Credential         json.RawMessage `json:"credential"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	idHash := auth.BlindIdentifier(s.cfg.IdentifierPepper, req.Identifier)
	if s.lockout.locked(idHash) {
		writeError(w, http.StatusTooManyRequests, "too many attempts; try again later")
		return
	}
	u, err := s.store.GetUserByIdentifierHash(r.Context(), idHash)
	if err != nil {
		s.lockout.recordFailure(idHash)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	ok, verr := auth.VerifyVerifier(u.MasterPasswordVerifier, req.MasterPasswordHash)
	if verr != nil || !ok {
		s.lockout.recordFailure(idHash)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	entry, found := s.waPending.take(req.SessionID)
	if !found || entry.userID != u.ID {
		writeError(w, http.StatusBadRequest, "passkey login expired; start again")
		return
	}
	parsed, perr := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(req.Credential))
	if perr != nil {
		writeError(w, http.StatusBadRequest, "invalid passkey assertion")
		return
	}
	waUser, _, uerr := s.webAuthnUserFor(r.Context(), u.ID)
	if uerr != nil {
		writeError(w, http.StatusInternalServerError, "login failed")
		return
	}
	cred, lerr := s.webAuthn.ValidateLogin(waUser, entry.data, parsed)
	if lerr != nil {
		s.lockout.recordFailure(idHash)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	// Persist the advanced signature counter for clone detection. A failure here
	// shouldn't fail an otherwise valid login.
	if err := s.store.UpdateWebAuthnSignCount(r.Context(), cred.ID, cred.Authenticator.SignCount); err != nil {
		s.logger.Error("webauthn update sign count", "err", err)
	}
	tokens, terr := s.issueTokens(r, u.ID)
	if terr != nil {
		s.logger.Error("issue tokens", "err", terr)
		writeError(w, http.StatusInternalServerError, "login failed")
		return
	}
	s.lockout.reset(idHash)
	writeJSON(w, http.StatusOK, loginResponse{
		AccessToken:      tokens.access,
		RefreshToken:     tokens.refresh,
		ProtectedUserKey: u.ProtectedUserKey,
		KDF:              u.KDF,
	})
}
