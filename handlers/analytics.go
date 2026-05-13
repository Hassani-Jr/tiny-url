package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"tiny-url/models"
	"tiny-url/services"
)

// AnalyticsHandler handles analytics requests
type AnalyticsHandler struct {
	storage services.Store
}

// NewAnalyticsHandler creates a new AnalyticsHandler
func NewAnalyticsHandler(storage services.Store) *AnalyticsHandler {
	return &AnalyticsHandler{
		storage: storage,
	}
}

// ServeHTTP returns analytics for a short code. Access requires the
// per-URL admin token returned at creation time, supplied as
// "Authorization: Bearer <token>". Expired short codes return 410 — the
// previous "show analytics for expired URLs anyway" path was an information
// leak and has been removed.
func (h *AnalyticsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	shortCode := r.PathValue("code")
	if shortCode == "" {
		writeError(w, http.StatusBadRequest, "Short code is required")
		return
	}

	urlMapping, err := h.storage.Get(shortCode)
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

	if !authorizeOwner(r, urlMapping.OwnerTokenHash) {
		writeError(w, http.StatusUnauthorized, "missing or invalid admin token")
		return
	}

	response := models.AnalyticsResponse{
		ShortCode:    urlMapping.ID,
		OriginalURL:  urlMapping.OriginalURL,
		ClickCount:   atomic.LoadInt64(&urlMapping.ClickCount),
		CreatedAt:    urlMapping.CreatedAt,
		ExpiresAt:    urlMapping.ExpiresAt,
		LastAccessed: urlMapping.LastAccessed,
		Tags:         urlMapping.Tags,
		MaxClicks:    urlMapping.MaxClicks,
		HasPassword:  len(urlMapping.PasswordHash) > 0,
	}

	w.Header().Set("Content-Type", "application/json")
	// Owner-only data: prevent intermediate caches (corporate proxies, dev
	// tools, browser extensions) from pinning the response.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}
