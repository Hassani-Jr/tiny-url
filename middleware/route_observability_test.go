package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"expvar"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

// TestMetricsCountsByRoute verifies the http_requests_route_total counter
// keys on the matched pattern. Two requests to different short codes that
// hit the same route increment the same counter — the whole reason for
// collapsing on r.Pattern instead of r.URL.Path.
func TestMetricsCountsByRoute(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("GET /api/url/{code}", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler := Metrics(mux)

	for _, code := range []string{"aaa", "bbb", "ccc"} {
		req := httptest.NewRequest(http.MethodGet, "/api/url/"+code, nil)
		req = req.WithContext(context.Background())
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}

	// expvar maps don't expose Get; serialize and inspect.
	dump := dumpExpvar(t)
	routeMap, ok := dump["http_requests_route_total"].(map[string]any)
	if !ok {
		t.Fatalf("http_requests_route_total missing or wrong type: %#v", dump["http_requests_route_total"])
	}
	key := "GET /api/url/{code}|2xx"
	got, ok := routeMap[key].(float64)
	if !ok || got < 3 {
		t.Errorf("counter[%q] = %v (type %T), want >= 3", key, routeMap[key], routeMap[key])
	}
}

// TestMetricsSkipsUnroutedRequests ensures unmatched paths don't pin
// per-path entries in the metrics map (an attacker spraying random paths
// could otherwise OOM the process).
func TestMetricsSkipsUnroutedRequests(t *testing.T) {
	// A handler that bypasses any ServeMux: r.Pattern stays "" and the
	// per-route counter must NOT increment, even though the status counter
	// does.
	handler := Metrics(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	beforeDump := dumpExpvar(t)
	beforeRoutes := 0
	if rm, ok := beforeDump["http_requests_route_total"].(map[string]any); ok {
		beforeRoutes = len(rm)
	}

	req := httptest.NewRequest(http.MethodGet, "/no-such-route", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	afterDump := dumpExpvar(t)
	afterRoutes := 0
	if rm, ok := afterDump["http_requests_route_total"].(map[string]any); ok {
		afterRoutes = len(rm)
	}
	if afterRoutes != beforeRoutes {
		t.Errorf("route map grew from %d → %d after unrouted request; should not", beforeRoutes, afterRoutes)
	}
}

// dumpExpvar marshals the global expvar registry into a generic map. We do
// this rather than reaching into expvar.Map's unexported state.
func dumpExpvar(t *testing.T) map[string]any {
	t.Helper()
	var sb strings.Builder
	sb.WriteByte('{')
	first := true
	expvar.Do(func(kv expvar.KeyValue) {
		if !first {
			sb.WriteByte(',')
		}
		first = false
		sb.WriteByte('"')
		sb.WriteString(kv.Key)
		sb.WriteString(`":`)
		sb.WriteString(kv.Value.String())
	})
	sb.WriteByte('}')
	var out map[string]any
	if err := json.Unmarshal([]byte(sb.String()), &out); err != nil {
		t.Fatalf("expvar dump parse: %v\n%s", err, sb.String())
	}
	return out
}
