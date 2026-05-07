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

func TestClicksHandlerHappyPath(t *testing.T) {
	store := services.NewMemoryStore()
	token := "click-token"
	hash := sha256.Sum256([]byte(token))
	_ = store.Set("c1", &models.URLMapping{
		ID: "c1", OriginalURL: "https://example.com", CreatedAt: time.Now(), OwnerTokenHash: hash[:],
	})
	for i := 0; i < 5; i++ {
		_ = store.RecordClick("c1", models.ClickEvent{
			At:      time.Now().Add(time.Duration(i) * time.Second),
			UAClass: "desktop",
		})
	}

	mux := http.NewServeMux()
	mux.Handle("GET /api/analytics/{code}/clicks", NewClicksHandler(store, 200))

	req := httptest.NewRequest(http.MethodGet, "/api/analytics/c1/clicks", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp clicksResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != 5 || len(resp.Events) != 5 {
		t.Errorf("count = %d (events=%d), want 5/5", resp.Count, len(resp.Events))
	}
}

func TestClicksHandlerLimitClampedToMax(t *testing.T) {
	store := services.NewMemoryStore()
	token := "tok"
	hash := sha256.Sum256([]byte(token))
	_ = store.Set("c2", &models.URLMapping{
		ID: "c2", OriginalURL: "https://example.com", CreatedAt: time.Now(), OwnerTokenHash: hash[:],
	})
	for i := 0; i < 50; i++ {
		_ = store.RecordClick("c2", models.ClickEvent{At: time.Now()})
	}
	mux := http.NewServeMux()
	mux.Handle("GET /api/analytics/{code}/clicks", NewClicksHandler(store, 10)) // max=10

	req := httptest.NewRequest(http.MethodGet, "/api/analytics/c2/clicks?limit=999", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp clicksResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Count != 10 {
		t.Errorf("count = %d, want 10 (clamped to maxLimit)", resp.Count)
	}
}

func TestClicksHandlerRequiresOwnerToken(t *testing.T) {
	store := services.NewMemoryStore()
	hash := sha256.Sum256([]byte("real"))
	_ = store.Set("c3", &models.URLMapping{
		ID: "c3", OriginalURL: "https://example.com", CreatedAt: time.Now(), OwnerTokenHash: hash[:],
	})
	mux := http.NewServeMux()
	mux.Handle("GET /api/analytics/{code}/clicks", NewClicksHandler(store, 200))

	req := httptest.NewRequest(http.MethodGet, "/api/analytics/c3/clicks", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}
