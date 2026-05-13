package handlers

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"tiny-url/models"
	"tiny-url/services"
)

func TestSeriesHandlerAuth(t *testing.T) {
	// Series exposes per-bucket temporal data — must be owner-token-gated
	// the same way plain analytics is.
	store := services.NewMemoryStore()
	hash := sha256OfString("tok")
	store.Set("s1", &models.URLMapping{
		ID: "s1", OriginalURL: "https://example.com", CreatedAt: time.Now(),
		OwnerTokenHash: hash,
	})
	h := NewSeriesHandler(store)
	mux := http.NewServeMux()
	mux.Handle("GET /api/analytics/{code}/series", h)

	req := httptest.NewRequest("GET", "/api/analytics/s1/series", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated status = %d, want 401", w.Code)
	}

	req = httptest.NewRequest("GET", "/api/analytics/s1/series", nil)
	req.Header.Set("Authorization", "Bearer tok")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("authenticated status = %d, want 200", w.Code)
	}
}

func TestSeriesHandlerBuckets(t *testing.T) {
	store := services.NewMemoryStore()
	hash := sha256OfString("tok")
	store.Set("sb", &models.URLMapping{
		ID: "sb", OriginalURL: "https://example.com", CreatedAt: time.Now(),
		OwnerTokenHash: hash,
	})

	// 3 clicks within the same hour (newest hour); a request for hour
	// buckets with range=2 should report [0, 3].
	now := time.Now()
	for i := 0; i < 3; i++ {
		store.RecordClick("sb", models.ClickEvent{At: now.Add(-time.Duration(i) * time.Minute)})
	}

	h := NewSeriesHandler(store)
	mux := http.NewServeMux()
	mux.Handle("GET /api/analytics/{code}/series", h)

	req := httptest.NewRequest("GET", "/api/analytics/sb/series?bucket=hour&range=2", nil)
	req.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp seriesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Bucket != "hour" || resp.BucketSecs != 3600 {
		t.Errorf("bucket=%q secs=%d, want hour/3600", resp.Bucket, resp.BucketSecs)
	}
	if len(resp.Counts) != 2 {
		t.Fatalf("counts len = %d, want 2", len(resp.Counts))
	}
	// All 3 events sit in the newest bucket (which is the LAST element of
	// the oldest-first array).
	if resp.Counts[1] != 3 {
		t.Errorf("counts[1] = %d, want 3 (current hour)", resp.Counts[1])
	}
}

func TestSeriesHandlerBadParams(t *testing.T) {
	store := services.NewMemoryStore()
	hash := sha256OfString("tok")
	store.Set("sp", &models.URLMapping{
		ID: "sp", OriginalURL: "https://example.com", CreatedAt: time.Now(),
		OwnerTokenHash: hash,
	})
	h := NewSeriesHandler(store)
	mux := http.NewServeMux()
	mux.Handle("GET /api/analytics/{code}/series", h)

	cases := []struct {
		name string
		path string
	}{
		{"bad bucket", "/api/analytics/sp/series?bucket=year"},
		{"bad range", "/api/analytics/sp/series?range=abc"},
		{"zero range", "/api/analytics/sp/series?range=0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.path, nil)
			req.Header.Set("Authorization", "Bearer tok")
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", w.Code)
			}
		})
	}
}

// sha256OfString computes the same hash the auth path expects for a given
// bearer token (since the storage layer holds the SHA-256, not the raw token).
func sha256OfString(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}
