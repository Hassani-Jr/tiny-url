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

func TestBulkShortenMixedSuccessAndFailure(t *testing.T) {
	// Three items: one valid, one with a bad URL (SSRF block), one
	// with a custom code collision (pre-populated). The bulk endpoint
	// must succeed item 1, fail items 2 and 3, and return 200 OK with
	// per-item statuses — NOT 4xx overall.
	store := services.NewMemoryStore()
	store.Set("taken", &models.URLMapping{
		ID: "taken", OriginalURL: "https://1.1.1.1/", CreatedAt: time.Now(),
	})

	single := NewShortenHandler(store, "http://localhost:8080", 525600, 4096, nil)
	bulk := NewBulkShortenHandler(single, 50)

	body := bulkShortenRequest{
		Items: []models.ShortenRequest{
			{URL: "https://1.1.1.1/ok"},
			{URL: "http://127.0.0.1/private"}, // SSRF
			{URL: "https://1.1.1.1/x", CustomCode: "taken"},
		},
	}
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest("POST", "/api/shorten/bulk", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	bulk.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (mixed-result responses are 200)", w.Code)
	}
	var resp bulkShortenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Created != 1 || resp.Failed != 2 {
		t.Errorf("counts = %d/%d, want 1/2 (created/failed)", resp.Created, resp.Failed)
	}
	if resp.Items[0].Result == nil || resp.Items[0].Error != nil {
		t.Errorf("item 0 should succeed: %+v", resp.Items[0])
	}
	if resp.Items[1].Result != nil || resp.Items[1].Error == nil {
		t.Errorf("item 1 should fail (SSRF): %+v", resp.Items[1])
	}
	if resp.Items[2].Error == nil || resp.Items[2].Error.Code != "code_conflict" {
		t.Errorf("item 2 should fail with code_conflict: %+v", resp.Items[2])
	}
}

func TestBulkShortenRejectsEmptyAndOversized(t *testing.T) {
	store := services.NewMemoryStore()
	single := NewShortenHandler(store, "http://localhost:8080", 525600, 4096, nil)
	bulk := NewBulkShortenHandler(single, 2) // tiny cap so we can hit it

	// Empty items array
	raw, _ := json.Marshal(bulkShortenRequest{Items: []models.ShortenRequest{}})
	r := httptest.NewRequest("POST", "/api/shorten/bulk", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	bulk.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("empty items: status = %d, want 400", w.Code)
	}

	// Over the per-request cap
	raw, _ = json.Marshal(bulkShortenRequest{Items: []models.ShortenRequest{
		{URL: "https://1.1.1.1/a"},
		{URL: "https://1.1.1.1/b"},
		{URL: "https://1.1.1.1/c"},
	}})
	r = httptest.NewRequest("POST", "/api/shorten/bulk", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	bulk.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("oversized: status = %d, want 400", w.Code)
	}
}

func TestBulkShortenWithAPIKeyClaimsAllItems(t *testing.T) {
	// Each successful item should be bound to the calling API key's
	// id, same as the single-item endpoint.
	store := services.NewMemoryStore()
	key := createAPIKey(t, store, "")
	single := NewShortenHandler(store, "http://localhost:8080", 525600, 4096, nil)
	bulk := NewBulkShortenHandler(single, 50)

	raw, _ := json.Marshal(bulkShortenRequest{Items: []models.ShortenRequest{
		{URL: "https://1.1.1.1/a"},
		{URL: "https://1.1.1.1/b"},
	}})
	r := httptest.NewRequest("POST", "/api/shorten/bulk", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+key.Token)
	w := httptest.NewRecorder()
	bulk.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	var resp bulkShortenResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	for _, item := range resp.Items {
		if item.Result == nil {
			t.Fatalf("item %d failed: %+v", item.Index, item.Error)
		}
		stored, _ := store.Get(item.Result.ShortCode)
		if stored.APIKeyID != key.ID {
			t.Errorf("item %d APIKeyID = %d, want %d", item.Index, stored.APIKeyID, key.ID)
		}
	}
}
