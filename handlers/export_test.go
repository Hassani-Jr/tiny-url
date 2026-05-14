package handlers

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tiny-url/models"
	"tiny-url/services"
)

// seedExportFixture provisions a code+token pair with `nEvents` click
// rows so each test can focus on the response shape without repeating
// the auth + seed dance.
func seedExportFixture(t *testing.T, store *services.MemoryStore, code, token string, nEvents int) {
	t.Helper()
	hash := sha256.Sum256([]byte(token))
	if err := store.Set(code, &models.URLMapping{
		ID: code, OriginalURL: "https://example.com",
		CreatedAt: time.Now(), OwnerTokenHash: hash[:],
	}); err != nil {
		t.Fatalf("seed Set: %v", err)
	}
	for i := range nEvents {
		_ = store.RecordClick(code, models.ClickEvent{
			At:      time.Now().Add(time.Duration(i) * time.Second),
			UAClass: "desktop",
			Country: "US",
			Referer: "https://news.example.com",
		})
	}
}

func TestExportHandlerCSV(t *testing.T) {
	store := services.NewMemoryStore()
	const code, token = "exp1", "tok"
	seedExportFixture(t, store, code, token, 3)

	mux := http.NewServeMux()
	mux.Handle("GET /api/analytics/{code}/export", NewExportHandler(store, 0))

	req := httptest.NewRequest(http.MethodGet, "/api/analytics/exp1/export?format=csv", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/csv") {
		t.Errorf("Content-Type = %q, want text/csv", got)
	}
	if got := w.Header().Get("Content-Disposition"); !strings.Contains(got, "attachment") || !strings.Contains(got, "exp1") {
		t.Errorf("Content-Disposition = %q, want attachment with code", got)
	}

	rows, err := csv.NewReader(w.Body).ReadAll()
	if err != nil {
		t.Fatalf("csv parse: %v", err)
	}
	if len(rows) != 4 { // header + 3 events
		t.Fatalf("row count = %d, want 4 (header+3)", len(rows))
	}
	want := []string{"at", "ua_class", "referer", "country", "ip_hash", "destination_url"}
	for i, h := range want {
		if rows[0][i] != h {
			t.Errorf("header[%d] = %q, want %q", i, rows[0][i], h)
		}
	}
	// Spot-check one body row to make sure fields are populated.
	if rows[1][1] != "desktop" || rows[1][3] != "US" {
		t.Errorf("first body row = %v, want ua_class=desktop country=US", rows[1])
	}
}

func TestExportHandlerJSON(t *testing.T) {
	store := services.NewMemoryStore()
	const code, token = "exp2", "tok2"
	seedExportFixture(t, store, code, token, 2)

	mux := http.NewServeMux()
	mux.Handle("GET /api/analytics/{code}/export", NewExportHandler(store, 0))

	req := httptest.NewRequest(http.MethodGet, "/api/analytics/exp2/export?format=json", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	var resp struct {
		ShortCode string              `json:"short_code"`
		Count     int                 `json:"count"`
		Events    []models.ClickEvent `json:"events"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v\nbody=%s", err, w.Body.String())
	}
	if resp.ShortCode != code || resp.Count != 2 || len(resp.Events) != 2 {
		t.Errorf("resp = %+v, want code=%s count=2 len(events)=2", resp, code)
	}
}

func TestExportHandlerRequiresOwnerToken(t *testing.T) {
	store := services.NewMemoryStore()
	const code, token = "exp3", "tok3"
	seedExportFixture(t, store, code, token, 1)

	mux := http.NewServeMux()
	mux.Handle("GET /api/analytics/{code}/export", NewExportHandler(store, 0))

	req := httptest.NewRequest(http.MethodGet, "/api/analytics/exp3/export", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestExportHandlerRejectsUnknownFormat(t *testing.T) {
	store := services.NewMemoryStore()
	const code, token = "exp4", "tok4"
	seedExportFixture(t, store, code, token, 1)

	mux := http.NewServeMux()
	mux.Handle("GET /api/analytics/{code}/export", NewExportHandler(store, 0))

	req := httptest.NewRequest(http.MethodGet, "/api/analytics/exp4/export?format=xml", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for unknown format", w.Code)
	}
}
