package services

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// WebhookEvent is the per-click work item enqueued for asynchronous
// delivery. Payload is pre-marshalled JSON so the redirect handler doesn't
// pay the marshal cost on the hot path (and so the dispatcher's worker
// pool can ship bytes straight onto the wire). Secret is the HMAC-SHA256
// key; the signature header is recomputed in deliver() rather than
// pre-stamped so retries with a re-issued request body stay consistent.
type WebhookEvent struct {
	Code    string
	URL     string
	Secret  []byte
	Payload []byte
}

// WebhookDispatcher accepts WebhookEvents from the redirect path and
// delivers them asynchronously to owner-supplied targets. A bounded queue
// + a small worker pool keeps the cost predictable: a hot link can't
// spawn unbounded goroutines, and a slow webhook target can't stall the
// redirect path (Enqueue is non-blocking, drops on full queue).
//
// Retry policy: 3 attempts with exponential backoff (200ms, 800ms). 5xx
// responses retry; 2xx is success; 4xx is "the receiver says you're
// misconfigured" and is NOT retried — there's nothing the dispatcher can
// do to make a 401/403/422 succeed by trying again.
//
// SSRF defence: the destination host is re-validated at delivery time
// (ValidateHostAtRuntime) and the HTTP client refuses to follow
// redirects, so a 302 to 127.0.0.1 cannot bypass the create-time guard.
type WebhookDispatcher struct {
	queue   chan WebhookEvent
	client  *http.Client
	wg      sync.WaitGroup
	stopped atomic.Bool
	// hostValidator runs against the target host before every delivery to
	// close the DNS-rebinding window where create-time validation can be
	// invalidated. Defaults to ValidateHostAtRuntime; tests inject a
	// no-op so they can point at httptest.Server (which binds to
	// 127.0.0.1 and would otherwise trip the loopback guard).
	hostValidator func(host string) error
	// Metrics — incremented atomically; exposed via the expvar publishers
	// in package main if/when operators want to track delivery health.
	sent    atomic.Int64
	failed  atomic.Int64
	dropped atomic.Int64
}

// webhookSignatureHeader is the response header carrying the HMAC over the
// raw body. Format is "sha256=<hex>" so receivers can pick the algorithm
// out of the prefix and add other algorithms later without breaking
// existing verifiers (mirrors the convention used by GitHub).
const webhookSignatureHeader = "X-Tinyurl-Signature"

// NewWebhookDispatcher starts a worker pool sized by workers. queueSize
// bounds how many in-flight events can sit waiting for a worker before
// new events are dropped. timeout caps the per-attempt HTTP request
// duration; with the default 3 attempts a worst-case slow target ties up
// a worker for ~3*timeout + backoff.
func NewWebhookDispatcher(workers, queueSize int, timeout time.Duration) *WebhookDispatcher {
	if workers <= 0 {
		workers = 4
	}
	if queueSize <= 0 {
		queueSize = 256
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	d := &WebhookDispatcher{
		queue:         make(chan WebhookEvent, queueSize),
		hostValidator: ValidateHostAtRuntime,
		client: &http.Client{
			Timeout: timeout,
			// CheckRedirect: stop on the first 3xx. Following redirects on a
			// webhook delivery is a footgun — the receiver could 302 us to
			// http://127.0.0.1/ and bypass the runtime SSRF check below.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				// Conservative defaults — webhooks are bursty per-URL but the
				// overall pool is small, so we don't need an unbounded number
				// of idle connections per host.
				MaxIdleConnsPerHost: 4,
				IdleConnTimeout:     30 * time.Second,
				DisableCompression:  true,
			},
		},
	}
	for i := 0; i < workers; i++ {
		d.wg.Add(1)
		go d.worker()
	}
	return d
}

// Enqueue submits ev for asynchronous delivery. Non-blocking: returns
// false when the queue is full so callers (the redirect handler) never
// stall on a slow webhook target. The dropped counter ticks up so an
// operator can spot sustained backpressure in expvar.
func (d *WebhookDispatcher) Enqueue(ev WebhookEvent) bool {
	if d.stopped.Load() {
		return false
	}
	select {
	case d.queue <- ev:
		return true
	default:
		d.dropped.Add(1)
		return false
	}
}

// Close drains the in-flight events and stops the worker pool. Existing
// queued events are processed; further Enqueue calls return false. Safe
// to call multiple times.
func (d *WebhookDispatcher) Close() {
	if !d.stopped.CompareAndSwap(false, true) {
		return
	}
	close(d.queue)
	d.wg.Wait()
}

// Stats reports lifetime delivery counts. Useful in tests and for
// operator-visible metrics; not authoritative across restarts.
func (d *WebhookDispatcher) Stats() (sent, failed, dropped int64) {
	return d.sent.Load(), d.failed.Load(), d.dropped.Load()
}

func (d *WebhookDispatcher) worker() {
	defer d.wg.Done()
	for ev := range d.queue {
		d.deliver(ev)
	}
}

// deliver runs the actual HTTP POST with retry. Errors are logged but
// otherwise swallowed — the click itself has already been recorded by
// the time we get here, so a failed webhook is a downstream notification
// issue, not a data-loss issue.
func (d *WebhookDispatcher) deliver(ev WebhookEvent) {
	// Runtime SSRF check. The host's DNS could have been flipped to
	// 127.0.0.1 after the webhook was configured; re-resolving here
	// closes the rebinding window before we POST.
	parsed, err := url.Parse(ev.URL)
	if err != nil {
		d.failed.Add(1)
		slog.Warn("webhook: bad URL", "code", ev.Code, "err", err)
		return
	}
	if err := d.hostValidator(parsed.Hostname()); err != nil {
		d.failed.Add(1)
		slog.Warn("webhook: SSRF re-check failed", "code", ev.Code, "host", parsed.Hostname(), "err", err)
		return
	}

	sig := hmacSign(ev.Secret, ev.Payload)

	const maxAttempts = 3
	backoff := []time.Duration{0, 200 * time.Millisecond, 800 * time.Millisecond}
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(backoff[attempt])
		}
		retry, err := d.attempt(ev, sig)
		if err == nil {
			d.sent.Add(1)
			return
		}
		if !retry {
			d.failed.Add(1)
			slog.Warn("webhook: gave up", "code", ev.Code, "attempt", attempt+1, "err", err)
			return
		}
		slog.Debug("webhook: retrying", "code", ev.Code, "attempt", attempt+1, "err", err)
	}
	d.failed.Add(1)
	slog.Warn("webhook: exhausted retries", "code", ev.Code)
}

// attempt runs a single HTTP POST. Returns (retry, err): retry=true means
// the failure was transient (5xx, timeout, connection error) and the
// caller should back off and try again; retry=false means a terminal
// non-retryable response (2xx success → err is nil; 4xx → err non-nil).
func (d *WebhookDispatcher) attempt(ev WebhookEvent, sig []byte) (retry bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), d.client.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ev.URL, bytes.NewReader(ev.Payload))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(webhookSignatureHeader, "sha256="+hex.EncodeToString(sig))
	req.Header.Set("X-Tinyurl-Code", ev.Code)
	req.Header.Set("User-Agent", "tiny-url-webhook/1")

	resp, err := d.client.Do(req)
	if err != nil {
		// net.OpError, context.DeadlineExceeded, etc. — all retryable.
		var netErr net.Error
		if errors.As(err, &netErr) {
			return true, err
		}
		return true, err
	}
	defer resp.Body.Close()
	// Drain the body so the connection can be reused. Cap at 4KB —
	// receivers usually return small "ok" responses; anything bigger is
	// dropped.
	_, _ = io.CopyN(io.Discard, resp.Body, 4096)

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return false, nil
	case resp.StatusCode >= 500:
		return true, &httpStatusError{Status: resp.StatusCode}
	default:
		// 3xx (CheckRedirect aborted the request — receiver was trying to
		// redirect us, which we treat as misconfiguration) or 4xx.
		return false, &httpStatusError{Status: resp.StatusCode}
	}
}

// hmacSign computes HMAC-SHA256(secret, body). Constant-time signing isn't
// required (the inputs aren't attacker-controlled at this point) so we
// use the standard hmac.New / Write / Sum flow.
func hmacSign(secret, body []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write(body)
	return h.Sum(nil)
}

// httpStatusError lets retry logic inspect the status without depending
// on net/http internals.
type httpStatusError struct{ Status int }

func (e *httpStatusError) Error() string {
	return http.StatusText(e.Status)
}

// SetWebhookHostValidator overrides the dispatcher's per-delivery host
// validator. Intended for tests that need to point at httptest.Server
// (which binds to 127.0.0.1 and would otherwise trip the loopback
// guard). Production code never calls this.
func SetWebhookHostValidator(d *WebhookDispatcher, fn func(host string) error) {
	d.hostValidator = fn
}

// VerifyWebhookSignature is provided for symmetry — receivers (and our
// own tests) can call this to verify the X-Tinyurl-Signature header. The
// header value is the "sha256=<hex>" form emitted by deliver().
func VerifyWebhookSignature(secret, body []byte, header string) bool {
	const prefix = "sha256="
	if len(header) <= len(prefix) || header[:len(prefix)] != prefix {
		return false
	}
	got, err := hex.DecodeString(header[len(prefix):])
	if err != nil {
		return false
	}
	want := hmacSign(secret, body)
	return hmac.Equal(got, want)
}
