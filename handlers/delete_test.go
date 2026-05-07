package handlers

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"tiny-url/models"
	"tiny-url/services"
)

// muxWithDelete returns the same routing pattern main.go uses, so PathValue
// resolution against {code} matches production rather than the handler's
// raw ServeHTTP behaviour.
func muxWithDelete(h *DeleteHandler) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("DELETE /api/url/{code}", h)
	return mux
}

func TestDeleteHandler(t *testing.T) {
	t.Run("happy path 204 with valid token", func(t *testing.T) {
		store := services.NewMemoryStore()
		token := "validtoken-happy"
		hash := sha256.Sum256([]byte(token))
		_ = store.Set("alive", &models.URLMapping{
			ID:             "alive",
			OriginalURL:    "https://example.com",
			CreatedAt:      time.Now(),
			OwnerTokenHash: hash[:],
		})

		req := httptest.NewRequest(http.MethodDelete, "/api/url/alive", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		muxWithDelete(NewDeleteHandler(store)).ServeHTTP(w, req)

		if w.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204; body=%s", w.Code, w.Body.String())
		}
		if store.Exists("alive") {
			t.Errorf("mapping should have been removed from the store")
		}
	})

	t.Run("missing token 401", func(t *testing.T) {
		store := services.NewMemoryStore()
		hash := sha256.Sum256([]byte("notthistoken"))
		_ = store.Set("guarded", &models.URLMapping{
			ID:             "guarded",
			OriginalURL:    "https://example.com",
			CreatedAt:      time.Now(),
			OwnerTokenHash: hash[:],
		})

		req := httptest.NewRequest(http.MethodDelete, "/api/url/guarded", nil)
		w := httptest.NewRecorder()
		muxWithDelete(NewDeleteHandler(store)).ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", w.Code)
		}
		if !store.Exists("guarded") {
			t.Errorf("mapping was deleted despite a missing token")
		}
	})

	t.Run("wrong token 401", func(t *testing.T) {
		store := services.NewMemoryStore()
		hash := sha256.Sum256([]byte("real"))
		_ = store.Set("guarded2", &models.URLMapping{
			ID:             "guarded2",
			OriginalURL:    "https://example.com",
			CreatedAt:      time.Now(),
			OwnerTokenHash: hash[:],
		})

		req := httptest.NewRequest(http.MethodDelete, "/api/url/guarded2", nil)
		req.Header.Set("Authorization", "Bearer wrong")
		w := httptest.NewRecorder()
		muxWithDelete(NewDeleteHandler(store)).ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", w.Code)
		}
		if !store.Exists("guarded2") {
			t.Errorf("mapping was deleted despite an invalid token")
		}
	})

	t.Run("unknown code 404", func(t *testing.T) {
		store := services.NewMemoryStore()
		req := httptest.NewRequest(http.MethodDelete, "/api/url/nope", nil)
		req.Header.Set("Authorization", "Bearer anytoken")
		w := httptest.NewRecorder()
		muxWithDelete(NewDeleteHandler(store)).ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", w.Code)
		}
	})

	t.Run("expired url 410", func(t *testing.T) {
		store := services.NewMemoryStore()
		token := "validtoken"
		hash := sha256.Sum256([]byte(token))
		past := time.Now().Add(-time.Hour)
		_ = store.Set("dead", &models.URLMapping{
			ID:             "dead",
			OriginalURL:    "https://example.com",
			CreatedAt:      time.Now().Add(-2 * time.Hour),
			ExpiresAt:      &past,
			OwnerTokenHash: hash[:],
		})
		req := httptest.NewRequest(http.MethodDelete, "/api/url/dead", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		muxWithDelete(NewDeleteHandler(store)).ServeHTTP(w, req)
		if w.Code != http.StatusGone {
			t.Errorf("status = %d, want 410", w.Code)
		}
	})
}
