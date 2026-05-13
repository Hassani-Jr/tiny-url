package handlers

import (
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"tiny-url/middleware"
	"tiny-url/models"
	"tiny-url/services"
)

// RedirectConfig bundles the optional knobs for the redirect path. All
// fields are zero-value safe — a Config{} produces a handler with no deny
// re-check, no IP-hashing, and rate-limiter-style proxy trust off.
type RedirectConfig struct {
	DenyList   *services.DenyList
	TrustProxy bool
	LogIP      bool // hash and store the client IP on each click event
	// Stream, if set, receives a Publish() call for every successful
	// redirect. Drives the live-clicks SSE endpoint. Nil disables the
	// fan-out (e.g. in tests).
	Stream *services.ClickStream
	// DNSCache, if set, memoises the runtime SSRF re-check across hot
	// URLs. Nil falls through to direct resolution on every redirect.
	DNSCache *services.DNSCache
}

// RedirectHandler handles URL redirect requests.
type RedirectHandler struct {
	storage services.Store
	cfg     RedirectConfig
}

// NewRedirectHandler creates a new RedirectHandler.
func NewRedirectHandler(storage services.Store, cfg RedirectConfig) *RedirectHandler {
	return &RedirectHandler{storage: storage, cfg: cfg}
}

// ServeHTTP looks up the short code, records the click, and 302s to the
// original URL. Click recording is best-effort: a write failure is logged
// but does not block the redirect, since failing the user's redirect over
// a missed analytics increment would be the wrong tradeoff.
//
// The deny list is re-checked here so a host added to the list AFTER a short
// URL was created stops resolving immediately, without waiting for the
// scheduled cleanup or a manual delete.
func (h *RedirectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	shortCode := r.PathValue("code")
	if shortCode == "" {
		http.NotFound(w, r)
		return
	}

	urlMapping, err := h.storage.Get(shortCode)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrNotFound):
			http.NotFound(w, r)
		case errors.Is(err, services.ErrExpired):
			w.WriteHeader(http.StatusGone)
			_, _ = w.Write([]byte("This URL has expired"))
		default:
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// Click-cap enforcement BEFORE the deny/SSRF re-checks because a Gone
	// URL should report Gone regardless of whether the (now-irrelevant)
	// destination is currently reachable. Reads ClickCount without the lock
	// because urlMapping was just returned from Get and the counter is
	// updated via atomic.AddInt64 in RecordClick — see the comment on
	// URLMapping.ClickCount for the memory-ordering rationale.
	if urlMapping.MaxClicks > 0 && atomic.LoadInt64(&urlMapping.ClickCount) >= urlMapping.MaxClicks {
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write([]byte("This URL has reached its click limit"))
		return
	}

	// Password gate. The interstitial is a self-contained HTML form posted
	// back to the same path; the handler treats GET and POST differently
	// based on whether a password field is present in the body. A correct
	// password falls through to the normal redirect path below.
	if len(urlMapping.PasswordHash) > 0 {
		if !h.passwordOK(w, r, urlMapping) {
			return
		}
	}

	// Re-evaluate the destination at redirect time. Two checks:
	//   1. Deny-list — operators may have blocked the host AFTER creation.
	//   2. Runtime host validation — the host's DNS may have been flipped
	//      to a private/metadata IP since creation (the SSRF rebinding
	//      threat). Re-resolving here closes that window.
	// Both failures return 451 so the user sees a uniform "no longer
	// available" rather than learning which control fired.
	if u, perr := url.Parse(urlMapping.OriginalURL); perr == nil {
		host := u.Hostname()
		if h.cfg.DenyList != nil && h.cfg.DenyList.Contains(host) {
			w.WriteHeader(http.StatusUnavailableForLegalReasons)
			_, _ = w.Write([]byte("This short URL has been disabled."))
			return
		}
		// Use the cache when available — it's nil-safe so this works
		// in tests that wire RedirectConfig{} without thinking about it.
		hostErr := h.cfg.DNSCache.ValidateHost(host)
		if hostErr != nil {
			slog.WarnContext(r.Context(), "destination host failed runtime validation",
				"code", shortCode, "host", host, "err", hostErr)
			w.WriteHeader(http.StatusUnavailableForLegalReasons)
			_, _ = w.Write([]byte("This short URL has been disabled."))
			return
		}
	}

	// Click bookkeeping is best-effort: a write failure logs and proceeds
	// rather than failing the user's redirect over a missed analytics row.
	// RecordClick is now atomic at the storage layer, so the counter and
	// event log can no longer drift — earlier comments about a possible
	// off-by-one between IncrementClicks and LogClick no longer apply.
	ev := models.ClickEvent{
		At:      time.Now(),
		Referer: services.TruncateReferer(r.Header.Get("Referer")),
		UAClass: services.ClassifyUserAgent(r.Header.Get("User-Agent")),
	}
	if h.cfg.LogIP {
		ev.IPHash = services.HashIP(middleware.ClientIP(r, h.cfg.TrustProxy))
	}
	if err := h.storage.RecordClick(shortCode, ev); err != nil {
		slog.WarnContext(r.Context(), "recordClick failed", "code", shortCode, "err", err)
	} else if h.cfg.Stream != nil {
		// Only publish AFTER RecordClick succeeded — otherwise an SSE
		// subscriber would see events that aren't reflected in the
		// canonical click_events table. Best-effort: Publish drops on a
		// full subscriber buffer rather than blocking the redirect.
		h.cfg.Stream.Publish(shortCode, ev)
	}

	http.Redirect(w, r, urlMapping.OriginalURL, http.StatusFound)
}

// passwordOK returns true when the request has presented the correct
// passphrase for a password-gated short URL. When false, it has already
// written the response (the interstitial form or an HTTP error). The
// caller MUST return without further writes when this returns false.
//
// Two flows:
//
//   GET  → render the form (no submission yet).
//   POST → read "password" from the form body and verify. On success,
//          fall through to the normal redirect path. On failure, re-render
//          the form with a non-leaking generic error.
//
// The form is rendered fresh on every request — there is no cookie or
// session. Each click of a password-protected link prompts again. This is
// the simplest implementation and avoids needing session storage; the
// rate limiter and the PBKDF2 cost mitigate brute-force.
func (h *RedirectHandler) passwordOK(w http.ResponseWriter, r *http.Request, m *models.URLMapping) bool {
	const (
		hintEmpty = ""
		hintWrong = "Incorrect password. Try again."
	)
	switch r.Method {
	case http.MethodPost:
		// MaxBytesReader bounds form parsing so a 1GiB body can't pin a
		// goroutine on the redirect path. 4KB easily fits any reasonable
		// passphrase plus the form's other fields.
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if err := r.ParseForm(); err != nil {
			renderPasswordForm(w, http.StatusBadRequest, m.ID, hintEmpty)
			return false
		}
		if !verifyPassword(r.PostFormValue("password"), m.PasswordHash, m.PasswordSalt) {
			renderPasswordForm(w, http.StatusUnauthorized, m.ID, hintWrong)
			return false
		}
		return true
	case http.MethodGet:
		renderPasswordForm(w, http.StatusOK, m.ID, hintEmpty)
		return false
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return false
	}
}

// passwordFormTmpl is the interstitial shown when a short URL is password-
// gated. The form posts back to the same path so a successful submission
// flows through ServeHTTP again, this time with the password attached.
// CSP-friendly: no inline event handlers, no external resources.
//
// The template is parsed once at package init via must() — a runtime parse
// error here is a programmer mistake, not a request-time concern.
var passwordFormTmpl = template.Must(template.New("pwform").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Password required</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
  body { font-family: system-ui, sans-serif; background: #0f1115; color: #e6e8ee; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 1rem; }
  .card { background: #1a1d24; border: 1px solid #2a2f3a; border-radius: 12px; padding: 2rem; max-width: 360px; width: 100%; box-shadow: 0 8px 24px rgba(0,0,0,0.35); }
  h1 { font-size: 1.15rem; margin: 0 0 0.25rem; }
  p.muted { color: #98a0ad; font-size: 0.85rem; margin: 0 0 1rem; }
  label { display: block; font-size: 0.85rem; margin-bottom: 0.4rem; }
  input[type=password] { width: 100%; box-sizing: border-box; padding: 0.6rem 0.7rem; border-radius: 8px; border: 1px solid #2a2f3a; background: #0f1115; color: #e6e8ee; font-size: 0.95rem; }
  input[type=password]:focus { outline: 2px solid #5b8dff; outline-offset: -1px; }
  button { width: 100%; margin-top: 0.9rem; padding: 0.6rem; background: #5b8dff; color: #0f1115; border: 0; border-radius: 8px; font-weight: 600; cursor: pointer; }
  button:hover { filter: brightness(1.08); }
  .err { background: rgba(255, 85, 85, 0.12); border: 1px solid rgba(255, 85, 85, 0.35); color: #ff8a8a; padding: 0.5rem 0.7rem; border-radius: 6px; font-size: 0.85rem; margin-bottom: 0.8rem; }
</style>
</head>
<body>
<form class="card" method="POST" action="/{{.Code}}" autocomplete="off">
  <h1>This link is password-protected</h1>
  <p class="muted">Enter the passphrase to continue to /{{.Code}}.</p>
  {{if .ErrorMsg}}<div class="err">{{.ErrorMsg}}</div>{{end}}
  <label for="password">Password</label>
  <input type="password" id="password" name="password" required autofocus>
  <button type="submit">Continue</button>
</form>
</body>
</html>`))

func renderPasswordForm(w http.ResponseWriter, status int, code, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Each render is unique to the request (error state can change) and the
	// form body contains the short code, so caches must not pin it.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = passwordFormTmpl.Execute(w, struct {
		Code     string
		ErrorMsg string
	}{Code: code, ErrorMsg: errMsg})
}
