package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"
)

// TestLoggerCapturesRoutePattern verifies that aggregating by `route`
// instead of `path` collapses dynamic short-code requests into one bucket.
// Without r.Pattern in the log line, every request to /aBc123 / /xYz999 /
// etc. would emit a different `path=` value and "top routes" queries would
// be dominated by literal codes.
func TestLoggerCapturesRoutePattern(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	// Inner mux is what sets r.Pattern. Wrapping in Logger then routing
	// through the mux mimics production: outer middleware → inner mux.
	mux := http.NewServeMux()
	mux.Handle("GET /api/url/{code}", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	handler := Logger(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/url/aBc123", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", w.Code)
	}

	// The slog handler emits one JSON object per call; parse it and look
	// for the route attribute.
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &entry); err != nil {
		t.Fatalf("decode log line: %v\n%s", err, buf.String())
	}
	if got, want := entry["route"], "GET /api/url/{code}"; got != want {
		t.Errorf("route = %v, want %q (full entry: %v)", got, want, entry)
	}
	if got, want := entry["path"], "/api/url/aBc123"; got != want {
		t.Errorf("path = %v, want %q", got, want)
	}
}

// TestLoggerSkipsHealthyProbeRoutes verifies that 2xx hits to /healthz,
// /readyz, /metrics, and /favicon.ico produce no log line. K8s probes hit
// these once a second per pod and would otherwise drown the request log.
func TestLoggerSkipsHealthyProbeRoutes(t *testing.T) {
	for _, pattern := range []string{
		"GET /healthz",
		"GET /readyz",
		"GET /metrics",
		"GET /favicon.ico",
	} {
		t.Run(pattern, func(t *testing.T) {
			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
			t.Cleanup(func() { slog.SetDefault(prev) })

			mux := http.NewServeMux()
			mux.Handle(pattern, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			handler := Logger(mux)

			path := strings.TrimPrefix(pattern, "GET ")
			req := httptest.NewRequest(http.MethodGet, path, nil)
			handler.ServeHTTP(httptest.NewRecorder(), req)

			if buf.Len() != 0 {
				t.Errorf("Logger should be silent on healthy %s; got: %s", pattern, buf.String())
			}
		})
	}
}

// TestLoggerLogsProbeFailures ensures non-2xx probes ARE logged — a sudden
// /readyz 503 needs to surface, not be swallowed.
func TestLoggerLogsProbeFailures(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	mux := http.NewServeMux()
	mux.Handle("GET /readyz", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	handler := Logger(mux)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if buf.Len() == 0 {
		t.Errorf("Logger should emit a line for failing probe; got nothing")
	}
}

// TestMetricsCountsByRoute verifies the per-route counter keys on the
// matched pattern. Two requests to different short codes that hit the
// same route increment the same counter — the whole reason for
// collapsing on r.Pattern instead of r.URL.Path.
func TestMetricsCountsByRoute(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("GET /api/url/{code}", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler := Metrics(mux)

	before := counterValue(t, "GET /api/url/{code}", "2xx")
	for _, code := range []string{"aaa", "bbb", "ccc"} {
		req := httptest.NewRequest(http.MethodGet, "/api/url/"+code, nil)
		req = req.WithContext(context.Background())
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}
	after := counterValue(t, "GET /api/url/{code}", "2xx")

	if got := after - before; got < 3 {
		t.Errorf("counter delta = %v, want >= 3", got)
	}
}

// TestMetricsUnroutedFoldsToSingleBucket ensures unmatched requests
// share one label tuple ("unmatched") rather than pinning a per-path
// series — an attacker spraying random paths must not be able to
// explode the label cardinality.
func TestMetricsUnroutedFoldsToSingleBucket(t *testing.T) {
	handler := Metrics(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	for _, p := range []string{"/no-such-1", "/no-such-2", "/no-such-3"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}

	got, err := countSeriesWithLabel("tinyurl_http_requests_total", "route", "unmatched")
	if err != nil {
		t.Fatalf("count series: %v", err)
	}
	// Exactly one series with label route=unmatched regardless of how
	// many distinct paths we hit.
	if got != 1 {
		t.Errorf("unmatched series count = %d, want 1 (label cardinality leaked)", got)
	}
}

// counterValue reads the current value of tinyurl_http_requests_total
// for the (route, status_class) label tuple. Returns 0 when the series
// doesn't exist yet (first observation).
func counterValue(t *testing.T, route, statusClass string) float64 {
	t.Helper()
	families, err := metricsRegistry.Gather()
	if err != nil {
		t.Fatalf("registry gather: %v", err)
	}
	for _, mf := range families {
		if mf.GetName() != "tinyurl_http_requests_total" {
			continue
		}
		for _, m := range mf.Metric {
			if hasLabel(m, "route", route) && hasLabel(m, "status_class", statusClass) {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// countSeriesWithLabel returns how many distinct series in the named
// metric family carry (labelName, labelValue). Used to assert label
// cardinality bounds.
func countSeriesWithLabel(metricName, labelName, labelValue string) (int, error) {
	families, err := metricsRegistry.Gather()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, mf := range families {
		if mf.GetName() != metricName {
			continue
		}
		for _, m := range mf.Metric {
			if hasLabel(m, labelName, labelValue) {
				n++
			}
		}
	}
	return n, nil
}

func hasLabel(m *dto.Metric, name, value string) bool {
	for _, lp := range m.Label {
		if lp.GetName() == name && lp.GetValue() == value {
			return true
		}
	}
	return false
}

