package middleware

import (
	"crypto/subtle"
	"expvar"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
)

// Metrics middleware feeds counters that are published via /metrics
// (expvar.Handler). The numbers stay coarse on purpose — request totals
// bucketed by status class and an in-flight gauge. Anything finer (per-route
// histograms, p99 latency) belongs in Prometheus / OpenTelemetry, which can
// scrape the same path or replace this entirely.
var (
	httpRequestsTotal      = expvar.NewMap("http_requests_total")
	httpRequestsRouteTotal = expvar.NewMap("http_requests_route_total")
	httpRequestsInFlight   = expvar.NewInt("http_requests_in_flight")
	inFlight               atomic.Int64
)

// Metrics increments the appropriate counters around the wrapped handler.
// Order in the chain: place it AFTER RequestID and BEFORE rate limiting so
// that rate-limited 429s are counted (they are real requests the operator
// should see), but inert path-traversal 404s on /static are still attributed
// to the right status class.
//
// Two counters are emitted:
//   - http_requests_total: keyed by status class ("2xx", "4xx", …) for
//     overall error-rate alerting.
//   - http_requests_route_total: keyed by the matched ServeMux pattern
//     (e.g. "GET /{code}|2xx") so operators can spot which endpoint is hot
//     or failing without parsing logs. Unmatched requests (which produce
//     a default 404) are skipped to avoid pinning unbounded keys from
//     attacker-controlled paths.
func Metrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpRequestsInFlight.Set(inFlight.Add(1))
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)
		httpRequestsInFlight.Set(inFlight.Add(-1))
		class := strconv.Itoa(wrapped.statusCode/100) + "xx"
		httpRequestsTotal.Add(class, 1)
		// r.Pattern is set by ServeMux when routing succeeds. Empty means
		// "no matching route", which we deliberately don't count by route
		// — those keys would be the request's literal path and an attacker
		// could OOM the metrics map by spraying random paths.
		if r.Pattern != "" {
			httpRequestsRouteTotal.Add(r.Pattern+"|"+class, 1)
		}
	})
}

// MetricsHandler returns the expvar JSON exposition handler. The endpoint
// includes runtime internals (cmdline, memstats) and per-route counters —
// not catastrophic to leak on its own, but useful intel for an attacker
// who is mapping the service. Most operators firewall /metrics; for those
// who can't, GatedMetricsHandler adds a static-token gate.
func MetricsHandler() http.Handler {
	return expvar.Handler()
}

// GatedMetricsHandler wraps MetricsHandler with a constant-time bearer-token
// check. Pass token="" to disable the gate (returns the bare handler) — that
// is the right choice when the endpoint is already firewalled or scraped on
// a private network. Pass a non-empty token (typically from a METRICS_TOKEN
// env var) to require Authorization: Bearer <token> on every scrape.
//
// The check is single-token (no rotation, no per-scraper credentials). That
// is appropriate for a metrics endpoint where the threat model is "stop a
// drive-by from learning my route counters", not "authenticate scrapers".
// If you need rotation, point Prometheus's bearer_token_file at a managed
// secret and rotate the env var on the server side.
func GatedMetricsHandler(token string) http.Handler {
	if token == "" {
		return MetricsHandler()
	}
	expected := []byte(token)
	inner := MetricsHandler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") ||
			subtle.ConstantTimeCompare([]byte(strings.TrimSpace(auth[len("Bearer "):])), expected) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		inner.ServeHTTP(w, r)
	})
}
