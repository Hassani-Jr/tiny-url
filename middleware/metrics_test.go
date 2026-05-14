package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGatedMetricsHandlerOpenWhenTokenEmpty(t *testing.T) {
	// Empty token reproduces the pre-gate behaviour (open Prometheus handler).
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

// TestMetricsExpositionFormat asserts the /metrics endpoint emits the
// Prometheus text format with our app's metric names. Catches a
// regression where the wrong registry handler is wired in (e.g. the
// global one with no tinyurl_* series) or where a metric name drifts.
func TestMetricsExpositionFormat(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("GET /probe", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler := Metrics(mux)

	probe := httptest.NewRequest(http.MethodGet, "/probe", nil)
	handler.ServeHTTP(httptest.NewRecorder(), probe)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	GatedMetricsHandler("").ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"tinyurl_http_requests_total",
		"tinyurl_http_request_duration_seconds",
		"tinyurl_http_requests_in_flight",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("exposition missing %q\nbody=%s", want, body)
		}
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
