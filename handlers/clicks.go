package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"tiny-url/models"
	"tiny-url/services"
)

// ClicksHandler returns the per-event click log for a short code. Same
// owner-token gate as plain analytics — the event log contains
// click-by-click metadata and must not leak to non-owners.
type ClicksHandler struct {
	storage  services.Store
	maxLimit int
}

// NewClicksHandler defaults maxLimit to 200 if zero. A cap exists because
// the response is built in memory; with large logs an unbounded request
// could pull thousands of rows in one go.
func NewClicksHandler(storage services.Store, maxLimit int) *ClicksHandler {
	if maxLimit <= 0 {
		maxLimit = 200
	}
	return &ClicksHandler{storage: storage, maxLimit: maxLimit}
}

type clicksResponse struct {
	ShortCode string              `json:"short_code"`
	Count     int                 `json:"count"`
	Events    []models.ClickEvent `json:"events"`
}

func (h *ClicksHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	if code == "" {
		writeError(w, http.StatusBadRequest, "Short code is required")
		return
	}

	urlMapping, err := h.storage.Get(code)
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

	if !authorizeAccess(r, urlMapping, h.storage) {
		writeError(w, http.StatusUnauthorized, "missing or invalid admin token")
		return
	}

	limit := h.maxLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, perr := strconv.Atoi(v); perr == nil && parsed > 0 {
			if parsed > h.maxLimit {
				parsed = h.maxLimit
			}
			limit = parsed
		}
	}

	events, err := h.storage.RecentClicks(code, limit)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	// Same rationale as the plain analytics handler — prevent caching of
	// owner-scoped click metadata.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(clicksResponse{
		ShortCode: code,
		Count:     len(events),
		Events:    events,
	})
}
