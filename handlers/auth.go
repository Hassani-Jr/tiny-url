package handlers

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

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
