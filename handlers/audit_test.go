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

func TestAuditHandlerOpenWithoutToken(t *testing.T) {
	// When METRICS_TOKEN is unset, the endpoint is open — same posture
	// as /metrics. Useful for operators on a private network.
	store := services.NewMemoryStore()
	store.LogAudit(models.AuditEvent{
		At:         time.Now(),
		ActorKind:  models.AuditActorAnon,
		Action:     models.AuditActionURLCreate,
		TargetKind: "url",
		TargetID:   "x",
	})
	h := NewAuditHandler(store, "")
	r := httptest.NewRequest("GET", "/api/audit", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestAuditHandlerGatedByToken(t *testing.T) {
	store := services.NewMemoryStore()
	h := NewAuditHandler(store, "op-secret")

	// No token → 401
	r := httptest.NewRequest("GET", "/api/audit", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", w.Code)
	}

	// Wrong token → 401
	r = httptest.NewRequest("GET", "/api/audit", nil)
	r.Header.Set("Authorization", "Bearer nope")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: status = %d, want 401", w.Code)
	}

	// Right token → 200
	r = httptest.NewRequest("GET", "/api/audit", nil)
	r.Header.Set("Authorization", "Bearer op-secret")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("right token: status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

func TestAuditHandlerReturnsLoggedEvents(t *testing.T) {
	store := services.NewMemoryStore()
	for i := 0; i < 3; i++ {
		store.LogAudit(models.AuditEvent{
			At:         time.Now().Add(time.Duration(i) * time.Second),
			ActorKind:  models.AuditActorAPIKey,
			ActorID:    "7",
			Action:     models.AuditActionURLCreate,
			TargetKind: "url",
			TargetID:   "url-" + string(rune('a'+i)),
		})
	}
	h := NewAuditHandler(store, "")
	r := httptest.NewRequest("GET", "/api/audit?limit=10", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	var resp auditResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Events) != 3 {
		t.Errorf("events = %d, want 3", len(resp.Events))
	}
}

// TestShortenLogsAudit verifies the create handler hits LogAudit.
// Catches accidental removal of the call site during a future refactor.
func TestShortenLogsAudit(t *testing.T) {
	store := services.NewMemoryStore()
	h := NewShortenHandler(store, "http://localhost:8080", 525600, 4096, nil)

	body := []byte(`{"url":"https://1.1.1.1/"}`)
	r := httptest.NewRequest("POST", "/api/shorten", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}

	events, _ := store.RecentAuditEvents(10, 0)
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event after shorten, got %d", len(events))
	}
	if events[0].Action != models.AuditActionURLCreate {
		t.Errorf("action = %q, want %q", events[0].Action, models.AuditActionURLCreate)
	}
	if events[0].ActorKind != models.AuditActorAnon {
		t.Errorf("actor = %q, want anon (no auth on this shorten)", events[0].ActorKind)
	}
}
