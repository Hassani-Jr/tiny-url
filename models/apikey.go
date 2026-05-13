package models

import "time"

// APIKey is the persisted record for an account-level credential. Unlike
// the per-URL admin token, an API key has identity (ID) and grants
// access to every URL whose `api_key_id` matches it.
//
// The plaintext key value is shown ONCE at creation; the server stores
// only TokenHash (SHA-256). Keys are independent — there's no
// user/account layer above them. Operators who want multi-key
// "households" can issue multiple keys and treat the labels as the
// per-device differentiator.
type APIKey struct {
	ID         int64      // monotonic; assigned by the store on insert
	TokenHash  []byte     // SHA-256 of the raw token
	Label      string     // owner-supplied; opaque to server (max 64 chars)
	CreatedAt  time.Time  //
	LastUsedAt *time.Time // updated lazily on successful auth; nil if never used
}

// CreateAPIKeyRequest is the POST /api/keys body.
type CreateAPIKeyRequest struct {
	Label string `json:"label,omitempty"`
}

// APIKeyResponse describes an API key WITHOUT the raw token — used for
// GET /api/keys after creation, when the plaintext is gone.
type APIKeyResponse struct {
	ID         int64      `json:"id"`
	Label      string     `json:"label,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// CreateAPIKeyResponse is returned by POST /api/keys. Token is the only
// time the raw value is exposed; downstream calls reference the key by
// the bearer header.
type CreateAPIKeyResponse struct {
	ID        int64     `json:"id"`
	Label     string    `json:"label,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	Token     string    `json:"token"`
}
