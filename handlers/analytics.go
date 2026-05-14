package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"sync/atomic"
	"tiny-url/models"
	"tiny-url/services"
)

// analyticsTopCountriesSample bounds how many recent click events the
// analytics handler pulls to compute the country breakdown. Picked to
// give a useful sample on busy URLs without making the handler O(N) on
// the full event log; the breakdown is intentionally a recent-window
// approximation, not a lifetime aggregate (a future store method could
// promote it to authoritative when it matters).
const analyticsTopCountriesSample = 1000

// analyticsTopCountriesLimit caps how many ISO codes ride along in the
// response. The dashboard renders a small list; beyond ~10 codes the
// long tail isn't useful and just bloats the payload for hot URLs.
const analyticsTopCountriesLimit = 10

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

	if !authorizeAccess(r, urlMapping, h.storage) {
		writeError(w, http.StatusUnauthorized, "missing or invalid admin token")
		return
	}

	response := models.AnalyticsResponse{
		ShortCode:          urlMapping.ID,
		OriginalURL:        urlMapping.OriginalURL,
		ClickCount:         atomic.LoadInt64(&urlMapping.ClickCount),
		CreatedAt:          urlMapping.CreatedAt,
		ExpiresAt:          urlMapping.ExpiresAt,
		LastAccessed:       urlMapping.LastAccessed,
		Tags:               urlMapping.Tags,
		MaxClicks:          urlMapping.MaxClicks,
		HasPassword:        len(urlMapping.PasswordHash) > 0,
		WebhookURL:         urlMapping.WebhookURL,
		PreviewTitle:       urlMapping.PreviewTitle,
		PreviewImage:       urlMapping.PreviewImage,
		PreviewDescription: urlMapping.PreviewDescription,
		PreviewFetchedAt:   urlMapping.PreviewFetchedAt,
		Destinations:       urlMapping.Destinations,
		TopCountries:       topCountries(h.storage, shortCode),
	}

	w.Header().Set("Content-Type", "application/json")
	// Owner-only data: prevent intermediate caches (corporate proxies, dev
	// tools, browser extensions) from pinning the response.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// topCountries pulls a recent slice of the click event log and tallies
// the country field. Empty ISO codes (geoip miss / disabled) are
// dropped — they'd otherwise form a single "unknown" bucket that drowns
// out the actual breakdown for low-volume URLs. Returns nil on any
// storage error or when no codes accumulated (json:omitempty then
// suppresses the field instead of emitting an empty array).
func topCountries(store services.Store, code string) []models.CountryCount {
	events, err := store.RecentClicks(code, analyticsTopCountriesSample)
	if err != nil || len(events) == 0 {
		return nil
	}
	counts := make(map[string]int64, 16)
	for _, ev := range events {
		if ev.Country == "" {
			continue
		}
		counts[ev.Country]++
	}
	if len(counts) == 0 {
		return nil
	}
	out := make([]models.CountryCount, 0, len(counts))
	for iso, n := range counts {
		out = append(out, models.CountryCount{ISO: iso, Count: n})
	}
	// Stable order: highest count first, ISO ascending on ties. Without
	// the secondary key the per-call hash-map iteration order would
	// shuffle response bodies on tied codes, which breaks naive
	// snapshot tests and confuses cache validators.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].ISO < out[j].ISO
	})
	if len(out) > analyticsTopCountriesLimit {
		out = out[:analyticsTopCountriesLimit]
	}
	return out
}
