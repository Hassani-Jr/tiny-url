package handlers

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
)

// authorizeOwner returns true when the request carries a bearer token whose
// SHA-256 hash matches expectedHash. Constant-time comparison prevents the
// response timing from leaking the stored hash one byte at a time.
//
// Shared by analytics and delete since both gate on the same per-URL
// admin token returned at create time.
func authorizeOwner(r *http.Request, expectedHash []byte) bool {
	if len(expectedHash) == 0 {
		return false
	}
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	token := strings.TrimSpace(auth[len(prefix):])
	if token == "" {
		return false
	}
	got := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(got[:], expectedHash) == 1
}
