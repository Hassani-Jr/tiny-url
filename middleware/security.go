package middleware

import "net/http"

// SecurityHeaders sets a baseline of HTTP response headers that block common
// browser-side attacks (clickjacking, MIME sniffing, referrer leaks, XSS via
// unexpected content sources). HSTS is only emitted when the server is serving
// over TLS — sending it over plain HTTP is a no-op for browsers but causes
// confusion when reading responses.
func SecurityHeaders(tlsEnabled bool) func(http.Handler) http.Handler {
	csp := "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Content-Security-Policy", csp)
			if tlsEnabled {
				h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}
