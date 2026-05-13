package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"tiny-url/services"
)

// SeriesHandler returns aggregated click counts as a fixed-width time
// series for the analytics sparkline. Same owner-token gate as plain
// analytics — buckets reveal the temporal distribution of clicks which is
// owner-only metadata.
//
// Query params:
//
//	bucket=minute|hour|day   defaults to "hour"
//	range=N                  bucket count; capped per resolution to keep
//	                         response sizes bounded (see rangeCaps).
//
// The response is intentionally compact — just the bucket width and an
// array of counts, oldest-first. Callers reconstruct timestamps from the
// `end` field (server-side `time.Now()` at request time) by subtracting
// multiples of bucket width.
type SeriesHandler struct {
	storage services.Store
}

func NewSeriesHandler(storage services.Store) *SeriesHandler {
	return &SeriesHandler{storage: storage}
}

// rangeCaps bounds the bucket count per resolution. Picked so the response
// stays under ~10KB JSON regardless of resolution, and so a coarse
// resolution can't be used to scan an unbounded amount of history.
var rangeCaps = map[string]struct {
	bucket time.Duration
	defN   int
	maxN   int
}{
	"minute": {bucket: time.Minute, defN: 60, maxN: 240},    // up to 4h
	"hour":   {bucket: time.Hour, defN: 24, maxN: 168},      // up to 7d
	"day":    {bucket: 24 * time.Hour, defN: 30, maxN: 365}, // up to 1y
}

type seriesResponse struct {
	ShortCode  string    `json:"short_code"`
	Bucket     string    `json:"bucket"`      // "minute" | "hour" | "day"
	BucketSecs int64     `json:"bucket_secs"` // width of each bucket in seconds (convenience for clients)
	End        time.Time `json:"end"`         // exclusive upper bound of the newest bucket
	Counts     []int64   `json:"counts"`      // oldest first; len == range
}

func (h *SeriesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	if !authorizeOwner(r, urlMapping.OwnerTokenHash) {
		writeError(w, http.StatusUnauthorized, "missing or invalid admin token")
		return
	}

	bucketName := r.URL.Query().Get("bucket")
	if bucketName == "" {
		bucketName = "hour"
	}
	cfg, ok := rangeCaps[bucketName]
	if !ok {
		writeError(w, http.StatusBadRequest, "bucket must be one of minute, hour, day")
		return
	}
	count := cfg.defN
	if v := r.URL.Query().Get("range"); v != "" {
		parsed, perr := strconv.Atoi(v)
		if perr != nil || parsed <= 0 {
			writeError(w, http.StatusBadRequest, "range must be a positive integer")
			return
		}
		if parsed > cfg.maxN {
			parsed = cfg.maxN
		}
		count = parsed
	}

	// Truncate `end` to a bucket boundary so successive requests with the
	// same parameters return aligned buckets (a sub-second jitter shouldn't
	// shift every bucket boundary by a few ms). Truncate to the bucket
	// width using integer arithmetic on unix nanoseconds.
	end := time.Now()
	w_ns := cfg.bucket.Nanoseconds()
	end = time.Unix(0, (end.UnixNano()/w_ns)*w_ns).Add(cfg.bucket)

	counts, err := h.storage.ClicksByBucket(code, end, cfg.bucket, count)
	if err != nil {
		if errors.Is(err, services.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(seriesResponse{
		ShortCode:  code,
		Bucket:     bucketName,
		BucketSecs: int64(cfg.bucket / time.Second),
		End:        end,
		Counts:     counts,
	})
}
