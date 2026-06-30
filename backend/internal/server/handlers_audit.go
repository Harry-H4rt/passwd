package server

import (
	"context"
	"net/http"
	"time"

	"github.com/passwd-app/server/internal/storage"
)

// Append-only security audit log. To preserve the zero-knowledge/no-PII stance it
// records the internal random account id and an event type only — never the
// plaintext identifier, and no IP. Users can review their own recent activity.

const auditListLimit = 100

// Event names. Stable strings the client can map to friendly labels.
const (
	evtRegister         = "account.register"
	evtLoginSuccess     = "login.success"
	evtLoginFailure     = "login.failure"
	evtTOTPEnable       = "totp.enable"
	evtTOTPDisable      = "totp.disable"
	evtPasskeyEnroll    = "passkey.enroll"
	evtPasskeyRemove    = "passkey.remove"
	evtRecoveryEnable   = "recovery.enable"
	evtRecoveryDisable  = "recovery.disable"
	evtRecoveryComplete = "recovery.complete"
	evtTokenReuse       = "token.reuse_detected"
	evtCipherCreate     = "cipher.create"
	evtCipherUpdate     = "cipher.update"
	evtCipherDelete     = "cipher.delete"
	evtShareCreate      = "share.create"
)

// audit records a security event. Failures are logged but never block the request
// the event describes. userID may be empty when the event is not attributable to a
// known account (e.g. a failed login for an unknown identifier — not recorded).
func (s *Server) audit(ctx context.Context, userID, event, detail string) {
	if userID == "" {
		return
	}
	if err := s.store.AppendAuditEvent(ctx, storage.AuditEvent{
		ID:        newID(),
		UserID:    userID,
		Event:     event,
		Detail:    detail,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		s.logger.Error("append audit event", "event", event, "err", err)
	}
}

type auditEventDTO struct {
	Event     string `json:"event"`
	Detail    string `json:"detail,omitempty"`
	CreatedAt string `json:"createdAt"`
}

// handleAuditLog returns the authenticated user's recent security events,
// newest first.
func (s *Server) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	events, err := s.store.ListAuditEvents(r.Context(), userID, auditListLimit)
	if err != nil {
		s.logger.Error("list audit events", "err", err)
		writeError(w, http.StatusInternalServerError, "could not load activity")
		return
	}
	out := make([]auditEventDTO, len(events))
	for i, e := range events {
		out[i] = auditEventDTO{Event: e.Event, Detail: e.Detail, CreatedAt: e.CreatedAt.Format(time.RFC3339)}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": out})
}
