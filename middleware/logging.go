package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

// probeRoutes are mux patterns whose successful traffic the Logger
// middleware skips. Kubernetes-style 1Hz liveness/readiness probes would
// otherwise produce 120+ log lines per minute and drown out real request
// logs. The Metrics middleware still counts them — operators who want to
// confirm probes are alive look at http_requests_route_total, not the log.
//
// Failures (non-2xx) are logged regardless: a sudden flood of /healthz 500s
// is exactly the signal you want surfaced.
var probeRoutes = map[string]bool{
	"GET /healthz":     true,
	"GET /readyz":      true,
	"GET /metrics":     true,
	"GET /favicon.ico": true,
}

// responseWriter wraps http.ResponseWriter to capture status and bytes written
// for downstream observability middleware. Shared across logging and metrics.
type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += n
	return n, err
}

// Logger emits one structured log line per request via slog. Status defaults
// to 200 if the handler never explicitly sets it (which mirrors Go's
// net/http behaviour). The request ID is included so log lines can be
// correlated with the X-Request-ID response header.
//
// route is the ServeMux pattern that matched (e.g., "GET /{code}"). It is
// read AFTER next.ServeHTTP because the inner mux only sets it during
// routing; by the time control returns to this middleware the most-deeply
// matched pattern is in place. Aggregating logs by `route` instead of
// `path` collapses every short-code redirect into one bucket — without it,
// "top URLs" queries are dominated by the literal short codes.
func Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)
		// Successful probe traffic is high-volume noise; non-2xx probes
		// still go through (a 503 from /readyz is actionable).
		if probeRoutes[r.Pattern] && wrapped.statusCode < 400 {
			return
		}
		slog.LogAttrs(r.Context(), slog.LevelInfo, "request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("route", r.Pattern),
			slog.Int("status", wrapped.statusCode),
			slog.Int("bytes", wrapped.bytesWritten),
			slog.Int64("duration_ms", time.Since(start).Milliseconds()),
			slog.String("remote_addr", r.RemoteAddr),
			slog.String("request_id", RequestIDFrom(r.Context())),
		)
	})
}
