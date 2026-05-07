package middleware

import (
	"expvar"
	"log/slog"
	"net/http"
	"runtime/debug"
)

// panicsTotal is incremented every time Recover catches a handler panic.
// Surfacing it in the metrics map lets operators alert on a sudden spike
// rather than discovering the problem only when somebody complains a page
// is broken.
var panicsTotal = expvar.NewInt("panics_total")

// Recover catches panics from downstream handlers and converts them into
// structured 500 responses. Without this, a panic kills the request mid-
// flight: Go's http.Server recovers the goroutine but dumps the trace to
// stderr (bypassing slog and the request_id) and the client sees a closed
// connection rather than a clean error.
//
// Place AFTER Logger and Metrics in the chain so their wrapped response
// writers observe the 500 status the recover branch sets here. Place BEFORE
// SecurityHeaders so the standard headers still ship on the error response.
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			rv := recover()
			if rv == nil {
				return
			}
			panicsTotal.Add(1)
			slog.ErrorContext(r.Context(), "panic recovered",
				"method", r.Method,
				"path", r.URL.Path,
				"route", r.Pattern,
				"request_id", RequestIDFrom(r.Context()),
				"panic", rv,
				"stack", string(debug.Stack()),
			)
			// Best-effort 500. If the handler already called WriteHeader
			// the status is locked in and net/http will log a "superfluous
			// WriteHeader" warning — that's fine; the original response is
			// already on the wire and there's nothing useful left to do.
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("internal server error"))
		}()
		next.ServeHTTP(w, r)
	})
}
