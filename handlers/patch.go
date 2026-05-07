package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"tiny-url/services"
)

// PatchHandler updates the destination URL and/or expiration of an existing
// short code. Owner-token gated, like DELETE and analytics. Mirrors the
// shorten handler's validation rules so a PATCH cannot smuggle a deny-listed
// or SSRF host past the create-time guards.
type PatchHandler struct {
	storage              services.Store
	maxExpirationMinutes int
	maxBodyBytes         int64
	denyList             *services.DenyList
}

func NewPatchHandler(storage services.Store, maxExpirationMinutes int, maxBodyBytes int64, denyList *services.DenyList) *PatchHandler {
	return &PatchHandler{
		storage:              storage,
		maxExpirationMinutes: maxExpirationMinutes,
		maxBodyBytes:         maxBodyBytes,
		denyList:             denyList,
	}
}

// patchRequest mirrors ShortenRequest but uses pointer fields so we can tell
// "field omitted from JSON" apart from "field set to zero value":
//
//   - URL=nil            → leave destination URL unchanged
//   - URL=""             → invalid (rejected); empty replacement makes no sense
//   - ExpirationMins=nil → leave expiration unchanged
//   - ExpirationMins=0   → REMOVE expiration (URL becomes never-expiring)
//   - ExpirationMins>0   → set expiration to N minutes from now
type patchRequest struct {
	URL            *string `json:"url"`
	ExpirationMins *int    `json:"expiration_mins"`
}

func (h *PatchHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	if code == "" {
		writeError(w, http.StatusBadRequest, "Short code is required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, h.maxBodyBytes)

	var req patchRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.URL == nil && req.ExpirationMins == nil {
		writeError(w, http.StatusBadRequest, "Provide at least one of url or expiration_mins")
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

	newURL := ""
	if req.URL != nil {
		if *req.URL == "" {
			writeError(w, http.StatusBadRequest, "url must be non-empty when provided")
			return
		}
		if err := services.ValidateDestinationURL(*req.URL, h.denyList); err != nil {
			writeError(w, http.StatusBadRequest, validationMessage(err))
			return
		}
		newURL = *req.URL
	}

	var (
		newExpiresAt    *time.Time
		clearExpiration bool
	)
	if req.ExpirationMins != nil {
		mins := *req.ExpirationMins
		switch {
		case mins < 0:
			writeError(w, http.StatusBadRequest, "expiration_mins must be non-negative")
			return
		case mins == 0:
			clearExpiration = true
		default:
			if mins > h.maxExpirationMinutes {
				mins = h.maxExpirationMinutes
			}
			t := time.Now().Add(time.Duration(mins) * time.Minute)
			newExpiresAt = &t
		}
	}

	if err := h.storage.Update(code, newURL, newExpiresAt, clearExpiration); err != nil {
		if errors.Is(err, services.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Re-read so the response reflects what was actually persisted (includes
	// upstream caps applied above).
	updated, err := h.storage.Get(code)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"short_code":   updated.ID,
		"original_url": updated.OriginalURL,
		"expires_at":   updated.ExpiresAt,
	})
}
