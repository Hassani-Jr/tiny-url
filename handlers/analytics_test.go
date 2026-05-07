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

func TestAnalyticsHandler(t *testing.T) {
	store := services.NewMemoryStore()
	handler := NewAnalyticsHandler(store)

	t.Run("missing bearer token", func(t *testing.T) {
		// Add a test code
		now := time.Now()
		store.Set("missing", &models.URLMapping{
			ID:          "missing",
			OriginalURL: "https://example.com",
			CreatedAt:   now,
		})

		mux := http.NewServeMux()
		mux.Handle("GET /api/analytics/{code}", handler)

		req := httptest.NewRequest("GET", "/api/analytics/missing", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", w.Code)
		}
	})

	t.Run("invalid bearer token", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.Handle("GET /api/analytics/{code}", handler)

		// Add a test URL
		now := time.Now()
		store.Set("test", &models.URLMapping{
			ID:          "test",
			OriginalURL: "https://example.com",
			CreatedAt:   now,
		})

		req := httptest.NewRequest("GET", "/api/analytics/test", nil)
		req.Header.Set("Authorization", "Bearer wrongtoken")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", w.Code)
		}
	})

	t.Run("code not found", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.Handle("GET /api/analytics/{code}", handler)

		req := httptest.NewRequest("GET", "/api/analytics/notfound", nil)
		req.Header.Set("Authorization", "Bearer anytoken")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", w.Code)
		}
	})
}

func TestAnalyticsHandlerWithValidToken(t *testing.T) {
	store := services.NewMemoryStore()
	handler := NewAnalyticsHandler(store)
	mux := http.NewServeMux()
	mux.Handle("GET /api/analytics/{code}", handler)

	// Create a URL with an owner token
	code := "test123"
	token := "validtoken123"
	tokenHash := sha256.Sum256([]byte(token))

	now := time.Now()
	store.Set(code, &models.URLMapping{
		ID:             code,
		OriginalURL:    "https://example.com",
		CreatedAt:      now,
		ClickCount:     42,
		OwnerTokenHash: tokenHash[:],
	})

	req := httptest.NewRequest("GET", "/api/analytics/"+code, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200, body: %s", w.Code, w.Body.String())
	}

	var resp models.AnalyticsResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	if err != nil {
		t.Errorf("response is not valid JSON: %v", err)
	}

	if resp.ShortCode != code {
		t.Errorf("short_code = %q, want %q", resp.ShortCode, code)
	}

	if resp.ClickCount != 42 {
		t.Errorf("click_count = %d, want 42", resp.ClickCount)
	}
}

func TestAnalyticsHandlerExpiredURL(t *testing.T) {
	store := services.NewMemoryStore()
	handler := NewAnalyticsHandler(store)
	mux := http.NewServeMux()
	mux.Handle("GET /api/analytics/{code}", handler)

	// Create an expired URL
	code := "expired"
	token := "validtoken"
	tokenHash := sha256.Sum256([]byte(token))

	now := time.Now()
	expiredTime := now.Add(-1 * time.Hour)
	store.Set(code, &models.URLMapping{
		ID:             code,
		OriginalURL:    "https://example.com",
		CreatedAt:      now,
		ExpiresAt:      &expiredTime,
		OwnerTokenHash: tokenHash[:],
	})

	req := httptest.NewRequest("GET", "/api/analytics/"+code, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusGone {
		t.Errorf("status = %d, want 410 (Gone)", w.Code)
	}
}

func TestAnalyticsHandlerClickCount(t *testing.T) {
	store := services.NewMemoryStore()
	handler := NewAnalyticsHandler(store)
	mux := http.NewServeMux()
	mux.Handle("GET /api/analytics/{code}", handler)

	code := "clicks"
	token := "token123"
	tokenHash := sha256.Sum256([]byte(token))

	now := time.Now()
	lastAccess := now.Add(-10 * time.Minute)

	store.Set(code, &models.URLMapping{
		ID:             code,
		OriginalURL:    "https://example.com",
		CreatedAt:      now,
		ClickCount:     100,
		LastAccessed:   &lastAccess,
		OwnerTokenHash: tokenHash[:],
	})

	req := httptest.NewRequest("GET", "/api/analytics/"+code, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp models.AnalyticsResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.ClickCount != 100 {
		t.Errorf("click_count = %d, want 100", resp.ClickCount)
	}

	if resp.LastAccessed == nil {
		t.Error("last_accessed should not be nil")
	}
}
