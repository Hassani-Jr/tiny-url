package handlers

import (
	"errors"
	"net/http"

	"tiny-url/services"
)

// DeleteHandler removes a short-code mapping. Gated by the same per-URL
// bearer token that grants analytics access — the token is the only
// "ownership" credential the system has.
//
// CSRF is intentionally NOT gated by RequireXRequestedWith here: the request
// already requires a hard-to-forge bearer token in an Authorization header,
// which a malicious cross-origin page cannot read out of the user's browser
// (it lives in localStorage on this origin). Adding XHR-header CSRF on top
// would only block legitimate curl users without raising the bar.
type DeleteHandler struct {
	storage services.Store
}

func NewDeleteHandler(storage services.Store) *DeleteHandler {
	return &DeleteHandler{storage: storage}
}

func (h *DeleteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	if code == "" {
		writeError(w, http.StatusBadRequest, "Short code is required")
		return
	}

	// Fetch the mapping so we can verify the owner token before deleting.
	// Expired URLs report 410 (matches analytics/redirect) — the cleanup
	// goroutine will reap them; the user doesn't need to manually delete.
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

	if err := h.storage.Delete(code); err != nil {
		if errors.Is(err, services.ErrNotFound) {
			// Lost a race with another deleter — treat as success.
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
