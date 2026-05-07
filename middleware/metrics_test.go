package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGatedMetricsHandlerOpenWhenTokenEmpty(t *testing.T) {
	// Empty token reproduces the pre-gate behaviour (open expvar handler).
	// Operators who firewall /metrics rely on this; we must not break them.
	h := GatedMetricsHandler("")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (open mode)", w.Code)
	}
}

func TestGatedMetricsHandlerRejectsMissingToken(t *testing.T) {
	h := GatedMetricsHandler("s3cr3t")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 when token absent", w.Code)
	}
	if got := w.Header().Get("WWW-Authenticate"); got == "" {
		t.Errorf("missing WWW-Authenticate challenge; got %q", got)
	}
}

func TestGatedMetricsHandlerRejectsWrongToken(t *testing.T) {
	h := GatedMetricsHandler("s3cr3t")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for wrong token", w.Code)
	}
}

func TestGatedMetricsHandlerAcceptsCorrectToken(t *testing.T) {
	h := GatedMetricsHandler("s3cr3t")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer s3cr3t")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 with valid token", w.Code)
	}
}

func TestGatedMetricsHandlerRejectsNonBearerScheme(t *testing.T) {
	// Basic auth with the same secret should NOT pass — the gate explicitly
	// requires the Bearer scheme so future scrape misconfigurations don't
	// silently match.
	h := GatedMetricsHandler("s3cr3t")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Basic s3cr3t")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for non-Bearer scheme", w.Code)
	}
}
