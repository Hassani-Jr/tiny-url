package handlers

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"tiny-url/models"
	"tiny-url/services"
)

func patchMux(h *PatchHandler) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("PATCH /api/url/{code}", h)
	return mux
}

func newPatchTestStore(t *testing.T, code string, exp *time.Time) (*services.MemoryStore, string) {
	t.Helper()
	store := services.NewMemoryStore()
	token := "patch-token-" + code
	hash := sha256.Sum256([]byte(token))
	_ = store.Set(code, &models.URLMapping{
		ID:             code,
		OriginalURL:    "https://old.example/",
		CreatedAt:      time.Now(),
		ExpiresAt:      exp,
		OwnerTokenHash: hash[:],
	})
	return store, token
}

func TestPatchHandlerUpdatesURL(t *testing.T) {
	store, token := newPatchTestStore(t, "p1", nil)
	h := NewPatchHandler(store, 525600, 4096, nil)

	body, _ := json.Marshal(map[string]any{"url": "https://1.1.1.1/new"})
	req := httptest.NewRequest(http.MethodPatch, "/api/url/p1", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	patchMux(h).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	got, _ := store.Get("p1")
	if got.OriginalURL != "https://1.1.1.1/new" {
		t.Errorf("URL = %q, want https://1.1.1.1/new", got.OriginalURL)
	}
}

func TestPatchHandlerClearsExpirationOnZero(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	store, token := newPatchTestStore(t, "p2", &exp)
	h := NewPatchHandler(store, 525600, 4096, nil)

	body, _ := json.Marshal(map[string]any{"expiration_mins": 0})
	req := httptest.NewRequest(http.MethodPatch, "/api/url/p2", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	patchMux(h).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	got, _ := store.Get("p2")
	if got.ExpiresAt != nil {
		t.Errorf("ExpiresAt = %v, want nil after expiration_mins=0", got.ExpiresAt)
	}
}

func TestPatchHandlerRejectsDeniedHost(t *testing.T) {
	store, token := newPatchTestStore(t, "p3", nil)
	deny := services.NewDenyList([]string{"phish.example"})
	h := NewPatchHandler(store, 525600, 4096, deny)

	body, _ := json.Marshal(map[string]any{"url": "https://www.phish.example/"})
	req := httptest.NewRequest(http.MethodPatch, "/api/url/p3", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	patchMux(h).ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for deny-listed host", w.Code)
	}
	got, _ := store.Get("p3")
	if got.OriginalURL != "https://old.example/" {
		t.Errorf("URL was changed despite deny-list: %q", got.OriginalURL)
	}
}

func TestPatchHandlerRequiresOwnerToken(t *testing.T) {
	store, _ := newPatchTestStore(t, "p4", nil)
	h := NewPatchHandler(store, 525600, 4096, nil)

	body, _ := json.Marshal(map[string]any{"url": "https://1.1.1.1/"})
	req := httptest.NewRequest(http.MethodPatch, "/api/url/p4", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer wrong")
	w := httptest.NewRecorder()
	patchMux(h).ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestPatchHandlerEmptyBodyRejected(t *testing.T) {
	store, token := newPatchTestStore(t, "p5", nil)
	h := NewPatchHandler(store, 525600, 4096, nil)

	req := httptest.NewRequest(http.MethodPatch, "/api/url/p5", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	patchMux(h).ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 when no fields supplied", w.Code)
	}
}
