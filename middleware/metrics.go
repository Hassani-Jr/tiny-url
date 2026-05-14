package middleware

import (
	"crypto/subtle"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics middleware feeds counters exposed via /metrics in the
// Prometheus text exposition format. We deliberately keep the label
// cardinality bounded: `route` is the matched ServeMux pattern (or
// "unmatched" when r.Pattern is empty), NOT the literal request path —
// otherwise a path-spraying attacker could pin an unbounded number of
// label-tuple series and OOM the process.
var (
	httpRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tinyurl_http_requests_total",
		Help: "Total HTTP requests handled, labelled by matched route and status class.",
	}, []string{"route", "status_class"})

	httpRequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "tinyurl_http_request_duration_seconds",
		Help:    "HTTP request latency by route and status class.",
		Buckets: prometheus.DefBuckets,
	}, []string{"route", "status_class"})

	httpRequestsInFlight = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "tinyurl_http_requests_in_flight",
		Help: "Number of HTTP requests currently being served.",
	})

	// inFlight backs the gauge with an atomic so the read/inc/set
	// sequence is consistent across goroutines under high concurrency.
	// The gauge.Set call is fed the post-increment value to avoid two
	// readers racing to publish stale numbers.
	inFlight atomic.Int64
)

// metricsRegistry is the registry exposed at /metrics. Kept private to
// the package so handlers don't accidentally register colliding metric
// names — if a caller needs to attach a metric they should add it here.
// Using a dedicated registry instead of prometheus.DefaultRegisterer
// keeps the exposition free of Go-runtime/process collectors by
// default; operators who want those can add them explicitly.
var metricsRegistry = prometheus.NewRegistry()

func init() {
	metricsRegistry.MustRegister(httpRequestsTotal)
	metricsRegistry.MustRegister(httpRequestDuration)
	metricsRegistry.MustRegister(httpRequestsInFlight)
	// Include process + Go runtime collectors so operators get RSS,
	// GC pause, goroutine count, etc. without per-deployment setup.
	// These are low-cardinality and standard for any Prometheus
	// exposition.
	metricsRegistry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	metricsRegistry.MustRegister(collectors.NewGoCollector())
}

// Metrics increments the appropriate counters around the wrapped handler.
// Order in the chain: place it AFTER RequestID and BEFORE rate limiting so
// that rate-limited 429s are counted (they are real requests the operator
// should see), but inert path-traversal 404s on /static are still
// attributed to the right status class. The matched route pattern is
// read AFTER next.ServeHTTP — ServeMux only sets r.Pattern during
// routing.
func Metrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpRequestsInFlight.Set(float64(inFlight.Add(1)))
		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)
		httpRequestsInFlight.Set(float64(inFlight.Add(-1)))

		class := strconv.Itoa(wrapped.statusCode/100) + "xx"
		route := routeLabel(r.Pattern)
		httpRequestsTotal.WithLabelValues(route, class).Inc()
		httpRequestDuration.WithLabelValues(route, class).Observe(time.Since(start).Seconds())
	})
}

// routeLabel maps r.Pattern to a bounded-cardinality label value.
// Unmatched requests (r.Pattern == "") fold into a single bucket so an
// attacker spraying random paths can't pin per-path label tuples.
func routeLabel(pattern string) string {
	if pattern == "" {
		return "unmatched"
	}
	return pattern
}

// MetricsHandler returns the Prometheus text-exposition handler bound
// to the package's private registry. The endpoint includes per-route
// counters and runtime stats; useful intel for an attacker mapping the
// service, so most operators firewall /metrics. For those who can't,
// GatedMetricsHandler adds a static-token gate.
func MetricsHandler() http.Handler {
	return promhttp.HandlerFor(metricsRegistry, promhttp.HandlerOpts{})
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
