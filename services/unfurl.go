package services

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/html"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

// UnfurlJob is the per-URL fetch request enqueued by the shorten
// handler. Code identifies the row to update once the fetch completes;
// URL is the destination to fetch. Both fields are required.
type UnfurlJob struct {
	Code string
	URL  string
}

// Unfurler asynchronously fetches a destination URL's HTML and extracts
// preview metadata (title, og:image, og:description) which it writes
// back to the URL row via Store.Update. The intended UX: a user
// creates a short URL, the response returns immediately, and the
// dashboard's preview card populates a moment later.
//
// Same SSRF / timeout / size posture as the WebhookDispatcher:
//
//   - hostValidator re-checks the destination at fetch time to close
//     the DNS-rebinding window (a hostile resolver could flip a
//     public address to 127.0.0.1 between create and fetch).
//   - HTTP client refuses to follow redirects so a 302 to internal
//     services can't bypass the SSRF guard.
//   - Body read is capped at maxBodyBytes; most og:* meta lives in
//     the first few KB, so 16KB is generous without letting a
//     hostile receiver stream gigabytes back.
type Unfurler struct {
	store         Store
	queue         chan UnfurlJob
	client        *http.Client
	maxBodyBytes  int64
	wg            sync.WaitGroup
	stopped       atomic.Bool
	hostValidator func(host string) error
	// counters exposed for tests / future expvar wiring
	fetched atomic.Int64
	failed  atomic.Int64
	dropped atomic.Int64
}

// NewUnfurler starts a worker pool that drains queue items. Tuning
// follows the webhook dispatcher's contract: workers <=0 → 4,
// queueSize <=0 → 256, timeout <=0 → 3s. Most successful fetches
// complete in well under 1s; the 3s ceiling covers slow CDNs without
// pinning a worker on a hung receiver.
func NewUnfurler(store Store, workers, queueSize int, timeout time.Duration) *Unfurler {
	if workers <= 0 {
		workers = 4
	}
	if queueSize <= 0 {
		queueSize = 256
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	base := &http.Transport{
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
		// Compression is helpful here: og: meta is in the head and
		// gzip lets us read more relevant content within the 16KB cap.
	}
	u := &Unfurler{
		store:         store,
		queue:         make(chan UnfurlJob, queueSize),
		hostValidator: ValidateHostAtRuntime,
		maxBodyBytes:  16 * 1024,
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: otelhttp.NewTransport(base),
		},
	}
	for i := 0; i < workers; i++ {
		u.wg.Add(1)
		go u.worker()
	}
	return u
}

// Enqueue submits j for asynchronous fetch. Non-blocking — drops on
// full queue so the calling redirect handler never stalls waiting for
// a slow downstream. The dropped counter ticks so an operator can
// catch sustained backpressure.
func (u *Unfurler) Enqueue(j UnfurlJob) bool {
	if u.stopped.Load() {
		return false
	}
	select {
	case u.queue <- j:
		return true
	default:
		u.dropped.Add(1)
		return false
	}
}

// Close drains in-flight jobs and shuts down the worker pool. Safe to
// call more than once.
func (u *Unfurler) Close() {
	if !u.stopped.CompareAndSwap(false, true) {
		return
	}
	close(u.queue)
	u.wg.Wait()
}

// Stats reports lifetime fetch counts for tests / metrics.
func (u *Unfurler) Stats() (fetched, failed, dropped int64) {
	return u.fetched.Load(), u.failed.Load(), u.dropped.Load()
}

var unfurlTracer = otel.Tracer("tiny-url/unfurl")

func (u *Unfurler) worker() {
	defer u.wg.Done()
	for j := range u.queue {
		u.fetch(j)
	}
}

// fetch performs the actual HTTP GET + parse + storage update. Always
// stamps preview_fetched_at on the row even when the fetch fails, so a
// retry policy could later distinguish "never tried" from "tried and
// got nothing" without an extra column. Failures are logged but
// swallowed — the URL still works without a preview, this is purely
// presentation.
func (u *Unfurler) fetch(j UnfurlJob) {
	ctx, span := unfurlTracer.Start(context.Background(), "unfurl.fetch")
	defer span.End()
	span.SetAttributes(
		attribute.String("tinyurl.code", j.Code),
	)

	preview, err := u.doFetch(ctx, j.URL)
	if err != nil {
		u.failed.Add(1)
		span.SetStatus(codes.Error, err.Error())
		slog.Debug("unfurl: fetch failed", "code", j.Code, "url", j.URL, "err", err)
		// Fall through anyway — we still want to stamp preview_fetched_at
		// so we don't retry this URL on the next restart's catch-up pass.
	} else {
		u.fetched.Add(1)
	}

	// Always run the update, even on an empty preview: stamping
	// preview_fetched_at is what tells a future operator "we already
	// tried this one." Empty title/image/desc are fine; the dashboard
	// just won't show a preview card.
	emptyTitle := preview.Title
	emptyImage := preview.Image
	emptyDesc := preview.Description
	if err := u.store.Update(j.Code, UpdateFields{
		PreviewTitle:       &emptyTitle,
		PreviewImage:       &emptyImage,
		PreviewDescription: &emptyDesc,
		SetPreviewFetched:  true,
	}); err != nil {
		// The URL row may have been deleted between Enqueue and now;
		// that's expected and noisy to surface, log at debug.
		slog.Debug("unfurl: storage update failed", "code", j.Code, "err", err)
	}
}

// previewParsed is the small struct the parser returns. Mirrors the
// shape that UpdateFields expects so the caller can plug it straight
// in without a translation step.
type previewParsed struct {
	Title       string
	Image       string
	Description string
}

func (u *Unfurler) doFetch(ctx context.Context, targetURL string) (previewParsed, error) {
	var out previewParsed
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return out, err
	}
	if err := u.hostValidator(parsed.Hostname()); err != nil {
		return out, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return out, err
	}
	req.Header.Set("User-Agent", "tiny-url-unfurl/1")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	// Asking for compressed responses lets us see more relevant
	// content within the body cap. The default Transport handles
	// transparent decompression.
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := u.client.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return out, errors.New("non-2xx response: " + resp.Status)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") && !strings.HasPrefix(ct, "application/xhtml+xml") {
		return out, errors.New("non-HTML content-type: " + ct)
	}

	// LimitReader caps the bytes we hand to the HTML parser. Most
	// og:* / <title> lives in the first few KB; 16KB is generous and
	// keeps an adversarial server from making us parse gigabytes.
	body := io.LimitReader(resp.Body, u.maxBodyBytes)
	out = parsePreview(body)
	return out, nil
}

// parsePreview walks the HTML token stream and pulls out the first
// <title> + the og:* / standard <meta> values. Stops as soon as
// </head> is seen — preview metadata only lives in <head>, so there's
// no point scanning the rest of the document.
//
// The parser is tolerant: a malformed input that returns ErrorToken
// just terminates the scan and returns whatever we've collected so
// far. Empty fields are fine; the dashboard hides the preview card
// when everything is blank.
func parsePreview(r io.Reader) previewParsed {
	var p previewParsed
	z := html.NewTokenizer(r)

	// Truncate caps: meta content can be arbitrarily long. 256 char
	// cap on title/description, 1024 on image URL — same shape as
	// the deny-list URL cap.
	const (
		maxTitleLen = 256
		maxDescLen  = 512
		maxImageLen = 1024
	)
	truncate := func(s string, n int) string {
		if len(s) > n {
			return s[:n]
		}
		return s
	}

	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			return p
		}
		if tt == html.EndTagToken {
			tok := z.Token()
			if tok.Data == "head" {
				return p
			}
			continue
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		tok := z.Token()
		switch tok.Data {
		case "title":
			if z.Next() == html.TextToken {
				if p.Title == "" {
					p.Title = truncate(strings.TrimSpace(z.Token().Data), maxTitleLen)
				}
			}
		case "meta":
			var key, content string
			for _, a := range tok.Attr {
				switch a.Key {
				case "property", "name":
					key = a.Val
				case "content":
					content = a.Val
				}
			}
			content = strings.TrimSpace(content)
			if content == "" {
				continue
			}
			switch key {
			case "og:title", "twitter:title":
				if p.Title == "" {
					p.Title = truncate(content, maxTitleLen)
				}
			case "og:image", "twitter:image":
				if p.Image == "" {
					p.Image = truncate(content, maxImageLen)
				}
			case "og:description", "twitter:description", "description":
				if p.Description == "" {
					p.Description = truncate(content, maxDescLen)
				}
			}
		}
	}
}

// SetUnfurlerHostValidator overrides the dispatcher's per-fetch host
// validator. Same escape hatch as SetWebhookHostValidator — production
// code never calls this, tests use it to point at httptest.Server.
func SetUnfurlerHostValidator(u *Unfurler, fn func(host string) error) {
	u.hostValidator = fn
}
