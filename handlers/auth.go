package handlers

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"tiny-url/middleware"
	"tiny-url/models"
	"tiny-url/services"
)

// extractBearer parses the Authorization header and returns the bearer
// token (trimmed) along with its SHA-256 hash. Empty hash signals
// "no usable token in this request" and short-circuits every auth path.
func extractBearer(r *http.Request) (token string, hash []byte) {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return "", nil
	}
	token = strings.TrimSpace(auth[len(prefix):])
	if token == "" {
		return "", nil
	}
	h := sha256.Sum256([]byte(token))
	return token, h[:]
}

// authorizeOwner returns true when the request carries a bearer token whose
// SHA-256 hash matches expectedHash. Constant-time comparison prevents the
// response timing from leaking the stored hash one byte at a time.
//
// Used by the per-URL flows that authenticate via the admin token only
// (rotate, which by design wants to re-key the URL from its current
// admin token).
func authorizeOwner(r *http.Request, expectedHash []byte) bool {
	if len(expectedHash) == 0 {
		return false
	}
	_, got := extractBearer(r)
	if got == nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, expectedHash) == 1
}

// authorizeAccess returns true when the request is authorized to read or
// modify the supplied URL mapping. Accepts either:
//
//  1. The URL's per-URL admin token (the original credential), OR
//  2. An API key whose ID matches mapping.APIKeyID (account-level
//     credential added in v2 #7).
//
// The check is short-circuited on the admin-token match so a caller
// holding only the URL token doesn't pay a storage lookup. Stores that
// implement LookupAPIKey return ErrNotFound for an unknown hash; the
// function treats both "no API key bound" and "key not found" as the
// same negative outcome.
func authorizeAccess(r *http.Request, mapping *models.URLMapping, store services.Store) bool {
	_, hash := extractBearer(r)
	if hash == nil {
		return false
	}
	// Admin token path. Constant-time compare to avoid a one-byte-at-a-
	// time timing leak of the stored hash.
	if len(mapping.OwnerTokenHash) > 0 &&
		subtle.ConstantTimeCompare(hash, mapping.OwnerTokenHash) == 1 {
		return true
	}
	// API key path. Only meaningful when the URL is bound to a key —
	// otherwise the lookup is a guaranteed miss and we save the round-
	// trip.
	if mapping.APIKeyID == 0 {
		return false
	}
	key, err := store.LookupAPIKey(hash)
	if err != nil {
		// Treat ErrNotFound and any other error as a refusal. We don't
		// log here — a wrong token is a routine event, not an alert.
		_ = errors.Is(err, services.ErrNotFound)
		return false
	}
	return key.ID == mapping.APIKeyID
}

// resolveActor inspects the request to figure out which credential
// authenticated it. Used by the audit-log call sites so each event
// records the right actor kind + id even though the per-URL handlers
// accept either credential via authorizeAccess.
//
// Returns:
//
//	("apikey", "<id>")           when the bearer is an API key
//	("admin_token", "<code>")    when the bearer is the URL's own admin token
//	("anon", "")                 when no recognized credential is present
//
// The mapping argument is optional — pass nil for endpoints that
// don't operate on a specific URL (e.g. POST /api/keys). When nil
// the function can only return "apikey" or "anon" since there's no
// admin-token hash to compare against.
func resolveActor(r *http.Request, mapping *models.URLMapping, store services.Store) (kind, id string) {
	_, hash := extractBearer(r)
	if hash == nil {
		return models.AuditActorAnon, ""
	}
	if mapping != nil && len(mapping.OwnerTokenHash) > 0 &&
		subtle.ConstantTimeCompare(hash, mapping.OwnerTokenHash) == 1 {
		return models.AuditActorAdminToken, mapping.ID
	}
	key, err := store.LookupAPIKey(hash)
	if err != nil || key == nil {
		return models.AuditActorAnon, ""
	}
	return models.AuditActorAPIKey, fmt.Sprintf("%d", key.ID)
}

// logAuditBestEffort fires an audit-log write and swallows the error
// after logging it. Used by every mutating handler — the user-visible
// op has already succeeded by the time we call this, so an audit write
// failure should never roll the operation back.
func logAuditBestEffort(store services.Store, ev models.AuditEvent) {
	if err := store.LogAudit(ev); err != nil {
		slog.Warn("audit log write failed",
			"action", ev.Action, "target", ev.TargetID, "err", err)
	}
}

// requestIDFromContext is a small wrapper over middleware.RequestIDFrom
// so audit-log call sites don't each have to spell out the chain.
func requestIDFromContext(r *http.Request) string {
	return middleware.RequestIDFrom(r.Context())
}
