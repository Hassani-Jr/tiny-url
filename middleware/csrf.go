package middleware

import "net/http"

// RequireXRequestedWith blocks requests that do not carry the
// "X-Requested-With: XMLHttpRequest" header. Setting this header from a
// cross-origin context triggers a CORS preflight, which the server does not
// permit — so a malicious page cannot forge a state-changing request from a
// victim's browser. This is the standard lightweight CSRF defence for APIs
// that don't issue session cookies.
func RequireXRequestedWith(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Requested-With") != "XMLHttpRequest" {
			http.Error(w, "missing required header X-Requested-With", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
