package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"tiny-url/middleware"
	"tiny-url/models"
	"tiny-url/services"
)

// RedirectConfig bundles the optional knobs for the redirect path. All
// fields are zero-value safe — a Config{} produces a handler with no deny
// re-check, no IP-hashing, and rate-limiter-style proxy trust off.
type RedirectConfig struct {
	DenyList   *services.DenyList
	TrustProxy bool
	LogIP      bool // hash and store the client IP on each click event
}

// RedirectHandler handles URL redirect requests.
type RedirectHandler struct {
	storage services.Store
	cfg     RedirectConfig
}

// NewRedirectHandler creates a new RedirectHandler.
func NewRedirectHandler(storage services.Store, cfg RedirectConfig) *RedirectHandler {
	return &RedirectHandler{storage: storage, cfg: cfg}
}

// ServeHTTP looks up the short code, records the click, and 302s to the
// original URL. Click recording is best-effort: a write failure is logged
// but does not block the redirect, since failing the user's redirect over
// a missed analytics increment would be the wrong tradeoff.
//
// The deny list is re-checked here so a host added to the list AFTER a short
// URL was created stops resolving immediately, without waiting for the
// scheduled cleanup or a manual delete.
func (h *RedirectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	shortCode := r.PathValue("code")
	if shortCode == "" {
		http.NotFound(w, r)
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

	// Re-evaluate the destination at redirect time. Two checks:
	//   1. Deny-list — operators may have blocked the host AFTER creation.
	//   2. Runtime host validation — the host's DNS may have been flipped
	//      to a private/metadata IP since creation (the SSRF rebinding
	//      threat). Re-resolving here closes that window.
	// Both failures return 451 so the user sees a uniform "no longer
	// available" rather than learning which control fired.
	if u, perr := url.Parse(urlMapping.OriginalURL); perr == nil {
		host := u.Hostname()
		if h.cfg.DenyList != nil && h.cfg.DenyList.Contains(host) {
			w.WriteHeader(http.StatusUnavailableForLegalReasons)
			_, _ = w.Write([]byte("This short URL has been disabled."))
			return
		}
		if err := services.ValidateHostAtRuntime(host); err != nil {
			slog.WarnContext(r.Context(), "destination host failed runtime validation",
				"code", shortCode, "host", host, "err", err)
			w.WriteHeader(http.StatusUnavailableForLegalReasons)
			_, _ = w.Write([]byte("This short URL has been disabled."))
			return
		}
	}

	// Click bookkeeping is best-effort: a write failure logs and proceeds
	// rather than failing the user's redirect over a missed analytics row.
	// RecordClick is now atomic at the storage layer, so the counter and
	// event log can no longer drift — earlier comments about a possible
	// off-by-one between IncrementClicks and LogClick no longer apply.
	ev := models.ClickEvent{
		At:      time.Now(),
		Referer: services.TruncateReferer(r.Header.Get("Referer")),
		UAClass: services.ClassifyUserAgent(r.Header.Get("User-Agent")),
	}
	if h.cfg.LogIP {
		ev.IPHash = services.HashIP(middleware.ClientIP(r, h.cfg.TrustProxy))
	}
	if err := h.storage.RecordClick(shortCode, ev); err != nil {
		slog.WarnContext(r.Context(), "recordClick failed", "code", shortCode, "err", err)
	}

	http.Redirect(w, r, urlMapping.OriginalURL, http.StatusFound)
}
