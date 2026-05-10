package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tiny-url/models"
	"tiny-url/services"
)

func badgeMux(h *BadgeHandler) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("GET /api/badge/{code}", h)
	return mux
}

func TestBadgeHandlerHappyPath(t *testing.T) {
	store := services.NewMemoryStore()
	_ = store.Set("bd1", &models.URLMapping{
		ID: "bd1", OriginalURL: "https://example.com",
		CreatedAt:  time.Now(),
		ClickCount: 42,
	})

	req := httptest.NewRequest(http.MethodGet, "/api/badge/bd1.svg", nil)
	w := httptest.NewRecorder()
	badgeMux(NewBadgeHandler(store)).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "image/svg+xml") {
		t.Errorf("Content-Type = %q, want image/svg+xml", ct)
	}
	cc := w.Header().Get("Cache-Control")
	if !strings.Contains(cc, "public") {
		t.Errorf("Cache-Control = %q, want public caching", cc)
	}
	body := w.Body.String()
	if !strings.Contains(body, "<svg") {
		t.Errorf("body should be SVG; got %q", body[:min(120, len(body))])
	}
	if !strings.Contains(body, "clicks") {
		t.Errorf("body should contain the 'clicks' label")
	}
	if !strings.Contains(body, "42") {
		t.Errorf("body should display the click count (42); body: %s", body)
	}
}

func TestBadgeHandlerWithoutDotSvgSuffix(t *testing.T) {
	// The mux captures the whole final segment as {code}; we strip ".svg"
	// inside the handler. Test that lookups still work without the suffix
	// (curl convenience, even though embeds will use .svg).
	store := services.NewMemoryStore()
	_ = store.Set("bd2", &models.URLMapping{
		ID: "bd2", OriginalURL: "https://example.com", CreatedAt: time.Now(), ClickCount: 7,
	})
	req := httptest.NewRequest(http.MethodGet, "/api/badge/bd2", nil)
	w := httptest.NewRecorder()
	badgeMux(NewBadgeHandler(store)).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "7") {
		t.Errorf("expected count 7 in SVG; body: %s", w.Body.String())
	}
}

func TestBadgeHandlerUnknownCode(t *testing.T) {
	store := services.NewMemoryStore()
	req := httptest.NewRequest(http.MethodGet, "/api/badge/nope.svg", nil)
	w := httptest.NewRecorder()
	badgeMux(NewBadgeHandler(store)).ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestBadgeHandlerExpiredCode(t *testing.T) {
	store := services.NewMemoryStore()
	past := time.Now().Add(-time.Hour)
	_ = store.Set("bd3", &models.URLMapping{
		ID: "bd3", OriginalURL: "https://example.com",
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: &past,
	})
	req := httptest.NewRequest(http.MethodGet, "/api/badge/bd3.svg", nil)
	w := httptest.NewRecorder()
	badgeMux(NewBadgeHandler(store)).ServeHTTP(w, req)
	if w.Code != http.StatusGone {
		t.Errorf("status = %d, want 410", w.Code)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
