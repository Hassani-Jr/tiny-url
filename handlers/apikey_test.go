package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"tiny-url/models"
	"tiny-url/services"
)

// helper: POST /api/keys against a fresh in-memory store, returns the
// raw token and full create response so subsequent tests can use it.
func createAPIKey(t *testing.T, store services.Store, label string) models.CreateAPIKeyResponse {
	t.Helper()
	h := NewAPIKeyHandler(store)
	body := []byte(`{"label":"` + label + `"}`)
	r := httptest.NewRequest("POST", "/api/keys", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201, body=%s", w.Code, w.Body.String())
	}
	var resp models.CreateAPIKeyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Token == "" {
		t.Fatal("token missing from response")
	}
	if resp.ID == 0 {
		t.Fatal("ID missing from response")
	}
	return resp
}

func TestAPIKeyCreateAndGet(t *testing.T) {
	store := services.NewMemoryStore()
	h := NewAPIKeyHandler(store)
	created := createAPIKey(t, store, "test-laptop")

	// GET with the right bearer returns the metadata WITHOUT the token.
	r := httptest.NewRequest("GET", "/api/keys", nil)
	r.Header.Set("Authorization", "Bearer "+created.Token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("get status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var got models.APIKeyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("ID = %d, want %d", got.ID, created.ID)
	}
	if got.Label != "test-laptop" {
		t.Errorf("Label = %q, want test-laptop", got.Label)
	}
	// The plaintext token must never appear in a GET response.
	if bytes.Contains(w.Body.Bytes(), []byte(created.Token)) {
		t.Error("plaintext token leaked in GET response")
	}
}

func TestAPIKeyUnauthorized(t *testing.T) {
	store := services.NewMemoryStore()
	h := NewAPIKeyHandler(store)

	cases := []string{"GET", "PATCH", "DELETE"}
	for _, m := range cases {
		t.Run(m, func(t *testing.T) {
			r := httptest.NewRequest(m, "/api/keys", bytes.NewReader([]byte(`{"label":"x"}`)))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Errorf("%s without auth: status = %d, want 401", m, w.Code)
			}
		})
	}
}

func TestAPIKeyDeleteClearsURLs(t *testing.T) {
	store := services.NewMemoryStore()
	created := createAPIKey(t, store, "")

	// Bind two URLs to this key.
	for _, code := range []string{"a1", "a2"} {
		store.Set(code, &models.URLMapping{
			ID: code, OriginalURL: "https://example.com", CreatedAt: time.Now(),
			APIKeyID: created.ID,
		})
	}

	h := NewAPIKeyHandler(store)
	r := httptest.NewRequest("DELETE", "/api/keys", nil)
	r.Header.Set("Authorization", "Bearer "+created.Token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204", w.Code)
	}

	// URLs survive but are disassociated.
	for _, code := range []string{"a1", "a2"} {
		m, err := store.Get(code)
		if err != nil {
			t.Errorf("Get(%s) after key delete: %v — URLs must survive", code, err)
			continue
		}
		if m.APIKeyID != 0 {
			t.Errorf("Get(%s).APIKeyID = %d, want 0 (cleared)", code, m.APIKeyID)
		}
	}
}

func TestMyURLsHandlerReturnsOnlyOwned(t *testing.T) {
	store := services.NewMemoryStore()
	keyA := createAPIKey(t, store, "A")
	keyB := createAPIKey(t, store, "B")

	store.Set("own-by-a", &models.URLMapping{
		ID: "own-by-a", OriginalURL: "https://a.example", CreatedAt: time.Now(),
		APIKeyID: keyA.ID,
	})
	store.Set("own-by-b", &models.URLMapping{
		ID: "own-by-b", OriginalURL: "https://b.example", CreatedAt: time.Now(),
		APIKeyID: keyB.ID,
	})
	store.Set("orphan", &models.URLMapping{
		ID: "orphan", OriginalURL: "https://orphan.example", CreatedAt: time.Now(),
	})

	h := NewMyURLsHandler(store, 100)
	r := httptest.NewRequest("GET", "/api/urls", nil)
	r.Header.Set("Authorization", "Bearer "+keyA.Token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		URLs []models.AnalyticsResponse `json:"urls"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.URLs) != 1 || resp.URLs[0].ShortCode != "own-by-a" {
		t.Errorf("URLs = %+v, want exactly [own-by-a]", resp.URLs)
	}
}

func TestAuthorizeAccessAcceptsAPIKey(t *testing.T) {
	// A URL owned by an API key must be readable via that key's bearer,
	// without anyone ever knowing the per-URL admin token.
	store := services.NewMemoryStore()
	key := createAPIKey(t, store, "owner")
	store.Set("urlA", &models.URLMapping{
		ID: "urlA", OriginalURL: "https://x.example", CreatedAt: time.Now(),
		OwnerTokenHash: sha256OfString("admin-tok"),
		APIKeyID:       key.ID,
	})

	mapping, err := store.Get("urlA")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	// API key bearer: allowed.
	r := httptest.NewRequest("GET", "/api/analytics/urlA", nil)
	r.Header.Set("Authorization", "Bearer "+key.Token)
	if !authorizeAccess(r, mapping, store) {
		t.Errorf("API key bearer rejected by authorizeAccess")
	}

	// Admin token bearer: also allowed.
	r2 := httptest.NewRequest("GET", "/api/analytics/urlA", nil)
	r2.Header.Set("Authorization", "Bearer admin-tok")
	if !authorizeAccess(r2, mapping, store) {
		t.Errorf("admin token bearer rejected by authorizeAccess")
	}

	// Wrong bearer: refused.
	r3 := httptest.NewRequest("GET", "/api/analytics/urlA", nil)
	r3.Header.Set("Authorization", "Bearer garbage")
	if authorizeAccess(r3, mapping, store) {
		t.Errorf("garbage bearer accepted by authorizeAccess")
	}
}

func TestShortenWithAPIKeyClaimsOwnership(t *testing.T) {
	store := services.NewMemoryStore()
	key := createAPIKey(t, store, "")
	h := NewShortenHandler(store, "http://localhost:8080", 525600, 4096, nil)

	body, _ := json.Marshal(models.ShortenRequest{URL: "https://1.1.1.1/"})
	r := httptest.NewRequest("POST", "/api/shorten", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+key.Token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	var resp models.ShortenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	stored, _ := store.Get(resp.ShortCode)
	if stored.APIKeyID != key.ID {
		t.Errorf("APIKeyID = %d, want %d — shorten with key bearer must claim ownership",
			stored.APIKeyID, key.ID)
	}
}
