package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"tiny-url/models"
	"tiny-url/services"
)

// fakePingStore wraps MemoryStore to inject a Ping error. We embed so we
// inherit the rest of the Store contract without re-implementing it.
type fakePingStore struct {
	*services.MemoryStore
	err error
}

func (f *fakePingStore) Ping(_ context.Context) error { return f.err }

var _ services.Store = (*fakePingStore)(nil)

// silence the "models imported and not used" stub if the test grows.
var _ = models.URLMapping{}

func TestReadyHandlerOK(t *testing.T) {
	h := NewReadyHandler(services.NewMemoryStore(), 100*time.Millisecond)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestReadyHandlerBackendDown(t *testing.T) {
	store := &fakePingStore{
		MemoryStore: services.NewMemoryStore(),
		err:         errors.New("boom"),
	}
	h := NewReadyHandler(store, 100*time.Millisecond)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
}
