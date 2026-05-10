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

func rotateMux(h *RotateHandler) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("POST /api/url/{code}/rotate", h)
	return mux
}

func TestRotateHandlerHappyPath(t *testing.T) {
	store := services.NewMemoryStore()
	oldToken := "old-token-1"
	oldHash := sha256.Sum256([]byte(oldToken))
	_ = store.Set("rot1", &models.URLMapping{
		ID: "rot1", OriginalURL: "https://example.com", CreatedAt: time.Now(),
		OwnerTokenHash: oldHash[:],
	})

	req := httptest.NewRequest(http.MethodPost, "/api/url/rot1/rotate", nil)
	req.Header.Set("Authorization", "Bearer "+oldToken)
	w := httptest.NewRecorder()
	rotateMux(NewRotateHandler(store)).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp rotateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.AdminToken == "" || resp.AdminToken == oldToken {
		t.Errorf("new token must be non-empty AND different from old: got %q", resp.AdminToken)
	}
	if resp.ShortCode != "rot1" {
		t.Errorf("short_code = %q, want rot1", resp.ShortCode)
	}

	// Old token must no longer authorize anything for this code.
	mapping, _ := store.Get("rot1")
	if !authorizeOwner(authReq("Bearer "+resp.AdminToken), mapping.OwnerTokenHash) {
		t.Error("new token should authorize the rotated code")
	}
	if authorizeOwner(authReq("Bearer "+oldToken), mapping.OwnerTokenHash) {
		t.Error("old token MUST NOT authorize after rotation")
	}
}

func TestRotateHandlerRejectsWrongToken(t *testing.T) {
	store := services.NewMemoryStore()
	hash := sha256.Sum256([]byte("real-token"))
	_ = store.Set("rot2", &models.URLMapping{
		ID: "rot2", OriginalURL: "https://example.com", CreatedAt: time.Now(),
		OwnerTokenHash: hash[:],
	})

	req := httptest.NewRequest(http.MethodPost, "/api/url/rot2/rotate", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	w := httptest.NewRecorder()
	rotateMux(NewRotateHandler(store)).ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	// Hash must NOT have changed when auth fails.
	mapping, _ := store.Get("rot2")
	if string(mapping.OwnerTokenHash) != string(hash[:]) {
		t.Error("hash was modified despite failed auth — leaks rotation to unauthenticated callers")
	}
}

func TestRotateHandlerUnknownCode(t *testing.T) {
	store := services.NewMemoryStore()
	req := httptest.NewRequest(http.MethodPost, "/api/url/nope/rotate", nil)
	req.Header.Set("Authorization", "Bearer anything")
	w := httptest.NewRecorder()
	rotateMux(NewRotateHandler(store)).ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func authReq(authHeader string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", authHeader)
	return r
}
