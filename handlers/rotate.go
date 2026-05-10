package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"tiny-url/services"
)

// RotateHandler issues a fresh admin token for a short code, invalidating
// the old one. The OLD token must be presented in Authorization — same
// gate as analytics/PATCH/DELETE — so an attacker who only knows the code
// (or has guessed it) cannot reset ownership.
//
// The new token is shown ONCE in the response, the same way create works.
// The server stores only its SHA-256 hash; the previous hash is overwritten
// atomically by services.Store.RotateToken.
type RotateHandler struct {
	storage services.Store
}

func NewRotateHandler(storage services.Store) *RotateHandler {
	return &RotateHandler{storage: storage}
}

type rotateResponse struct {
	ShortCode  string `json:"short_code"`
	AdminToken string `json:"admin_token"`
}

func (h *RotateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	if code == "" {
		writeError(w, http.StatusBadRequest, "Short code is required")
		return
	}

	mapping, err := h.storage.Get(code)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrNotFound):
			http.NotFound(w, r)
		case errors.Is(err, services.ErrExpired):
			w.WriteHeader(http.StatusGone)
			_, _ = w.Write([]byte("This URL has expired"))
		default:
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	if !authorizeOwner(r, mapping.OwnerTokenHash) {
		writeError(w, http.StatusUnauthorized, "missing or invalid admin token")
		return
	}

	// Generate a new token + hash. Same scheme as creation so the rotated
	// token is indistinguishable from a fresh one and the existing client
	// code that handles admin_token responses works unchanged.
	token, hash, err := generateOwnerToken()
	if err != nil {
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}

	if err := h.storage.RotateToken(code, hash); err != nil {
		if errors.Is(err, services.ErrNotFound) {
			// Lost a race with a delete; surface as 404.
			http.NotFound(w, r)
			return
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(rotateResponse{
		ShortCode:  code,
		AdminToken: token,
	})
}
