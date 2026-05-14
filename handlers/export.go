package handlers

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"tiny-url/models"
	"tiny-url/services"
)

// ExportHandler serves an owner-gated dump of a short code's click event
// log as CSV or JSON. It reuses the existing RecentClicks path rather
// than adding a streaming cursor to every Store backend — adequate for
// the typical "give me the last week" export and cheap to ship. The
// cap (exportMaxLimit) keeps a single export from materializing an
// unbounded slice in memory on the SQLite/Postgres backends.
type ExportHandler struct {
	storage  services.Store
	maxLimit int
}

// exportMaxLimit caps how many events a single export can pull. 50k
// keeps the response under a few megabytes (typical UA-class/referer
// rows are ~150 bytes), which sits well below the 30s WriteTimeout
// budget even on slow disks.
const exportMaxLimit = 50_000

// exportDefaultLimit is what callers get without ?limit=… set. Higher
// than the clicks endpoint's default because the export use case is
// "give me everything you have", not "show me the latest page".
const exportDefaultLimit = 5_000

// NewExportHandler returns a handler that defaults to exportMaxLimit
// when maxLimit <= 0. Callers can clamp it lower in tests.
func NewExportHandler(storage services.Store, maxLimit int) *ExportHandler {
	if maxLimit <= 0 {
		maxLimit = exportMaxLimit
	}
	return &ExportHandler{storage: storage, maxLimit: maxLimit}
}

func (h *ExportHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	// Format defaults to csv: the dashboard's existing "Export CSV"
	// button is the obvious caller, and CSV is the format every BI tool
	// and spreadsheet can ingest without a parser.
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "csv"
	}
	if format != "csv" && format != "json" {
		writeError(w, http.StatusBadRequest, "format must be csv or json")
		return
	}

	limit := exportDefaultLimit
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

	// Owner-scoped data; no shared cache should retain it. Same
	// rationale as /api/analytics/{code}.
	w.Header().Set("Cache-Control", "no-store")

	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf(`attachment; filename="tiny-url-%s-clicks.csv"`, code))
		writeClicksCSV(w, events)
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf(`attachment; filename="tiny-url-%s-clicks.json"`, code))
		// Mirror the /api/analytics/{code}/clicks shape so consumers can
		// reuse their event-decoding code without a parallel schema.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"short_code": code,
			"count":      len(events),
			"events":     events,
		})
	}
}

// writeClicksCSV emits a CSV with one row per event. The column order is
// the public, append-only contract — adding columns at the end is safe;
// reordering or removing breaks downstream importers.
func writeClicksCSV(w http.ResponseWriter, events []models.ClickEvent) {
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{
		"at", "ua_class", "referer", "country", "ip_hash", "destination_url",
	})
	for _, ev := range events {
		_ = cw.Write([]string{
			ev.At.UTC().Format("2006-01-02T15:04:05Z"),
			ev.UAClass,
			ev.Referer,
			ev.Country,
			ev.IPHash,
			ev.DestinationURL,
		})
	}
}
