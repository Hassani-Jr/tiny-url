package services

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"tiny-url/models"
)

func TestParsePreviewBasicTitleAndOG(t *testing.T) {
	doc := `<!DOCTYPE html><html><head>
	<title>Hello World</title>
	<meta property="og:title" content="OG Title — better than &lt;title&gt;">
	<meta property="og:image" content="https://example.com/img.png">
	<meta name="description" content="A simple page for testing.">
	</head><body>ignored</body></html>`
	p := parsePreview(strings.NewReader(doc))
	// og:title takes precedence over <title> only if <title> is
	// empty — our implementation prefers <title> if seen first.
	// Confirm both are at least populated.
	if p.Title == "" {
		t.Errorf("Title is empty; want non-empty")
	}
	if p.Image != "https://example.com/img.png" {
		t.Errorf("Image = %q, want og:image URL", p.Image)
	}
	if p.Description == "" {
		t.Errorf("Description is empty; want description meta")
	}
}

func TestParsePreviewTwitterFallback(t *testing.T) {
	// Some pages set twitter:* but not og:* — our parser should use
	// either.
	doc := `<html><head>
	<meta name="twitter:title" content="Tweeted Title">
	<meta name="twitter:image" content="https://example.com/t.png">
	</head></html>`
	p := parsePreview(strings.NewReader(doc))
	if p.Title != "Tweeted Title" {
		t.Errorf("Title = %q, want Tweeted Title (twitter fallback)", p.Title)
	}
	if p.Image != "https://example.com/t.png" {
		t.Errorf("Image = %q, want twitter image URL", p.Image)
	}
}

func TestParsePreviewMalformedReturnsPartial(t *testing.T) {
	// Truncated mid-tag: parser must terminate cleanly and return
	// whatever it managed to collect (in this case, the title).
	doc := `<html><head><title>Partial</title><meta property="og:image" cont`
	p := parsePreview(strings.NewReader(doc))
	if p.Title != "Partial" {
		t.Errorf("Title = %q, want Partial", p.Title)
	}
}

func TestUnfurlerHappyPath(t *testing.T) {
	// End-to-end: a tiny HTML page is served by httptest, the
	// Unfurler fetches it, parses, and the Update lands on the
	// supplied store.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><head>
		<title>Live Test</title>
		<meta property="og:image" content="https://example.com/x.png">
		</head></html>`))
	}))
	defer srv.Close()

	store := NewMemoryStore()
	_ = store.Set("u1", &models.URLMapping{
		ID: "u1", OriginalURL: srv.URL, CreatedAt: time.Now(),
	})

	u := NewUnfurler(store, 1, 8, 2*time.Second)
	SetUnfurlerHostValidator(u, func(string) error { return nil })
	defer u.Close()

	if !u.Enqueue(UnfurlJob{Code: "u1", URL: srv.URL}) {
		t.Fatal("Enqueue returned false")
	}
	// Wait for the worker to update the store. The fetch is fast
	// (~ms) but we poll to avoid a flaky fixed sleep.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		m, err := store.Get("u1")
		if err == nil && m.PreviewFetchedAt != nil {
			if m.PreviewTitle != "Live Test" {
				t.Errorf("Title = %q, want Live Test", m.PreviewTitle)
			}
			if m.PreviewImage != "https://example.com/x.png" {
				t.Errorf("Image = %q, want og image", m.PreviewImage)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("unfurl never landed on the store")
}

func TestUnfurlerSSRFBlocked(t *testing.T) {
	// With the real ValidateHostAtRuntime, an httptest URL (127.0.0.1)
	// must be rejected — and the Update should still stamp
	// preview_fetched_at so we don't retry forever.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Errorf("server should not have been called (SSRF guard must block)")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	store := NewMemoryStore()
	_ = store.Set("u2", &models.URLMapping{
		ID: "u2", OriginalURL: srv.URL, CreatedAt: time.Now(),
	})

	u := NewUnfurler(store, 1, 8, time.Second) // real validator
	defer u.Close()

	u.Enqueue(UnfurlJob{Code: "u2", URL: srv.URL})
	// Wait a bit so the worker definitely tried.
	time.Sleep(200 * time.Millisecond)

	m, _ := store.Get("u2")
	if m.PreviewFetchedAt == nil {
		t.Errorf("PreviewFetchedAt should be stamped even after a failed fetch")
	}
	if m.PreviewTitle != "" || m.PreviewImage != "" {
		t.Errorf("preview fields should be empty after SSRF block, got %+v", m)
	}
	if _, failed, _ := u.Stats(); failed != 1 {
		t.Errorf("failed = %d, want 1", failed)
	}
}
