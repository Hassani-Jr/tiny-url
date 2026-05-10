package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tiny-url/config"
	"tiny-url/services"
)

// TestEndToEndHappyPath drives the full real handler chain through
// httptest.NewServer. Everything between the wire and the storage layer
// is exercised: middleware (RequestID, Logger, Metrics, Recover,
// SecurityHeaders, rate-limiter), routing on appMux + outerMux, the
// embedded static assets, and the actual handlers.
//
// This is the test that catches mistakes the unit tests can't see —
// middleware ordering, route registration drift, embed paths, the
// X-Request-ID header escaping, etc.
func TestEndToEndHappyPath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.Config{
		BaseURL:              "http://127.0.0.1",
		MaxExpirationMinutes: 525600,
		MaxBodyBytes:         4096,
		// Rate limits high enough that the test never hits them.
		WriteRatePerMin: 1_000_000,
		ReadRatePerMin:  1_000_000,
		StorageBackend:  "memory",
	}
	store := services.NewMemoryStore()

	handler, err := buildHandler(ctx, cfg, store)
	if err != nil {
		t.Fatalf("buildHandler: %v", err)
	}

	srv := httptest.NewServer(handler)
	defer srv.Close()

	client := &http.Client{
		Timeout: 5 * time.Second,
		// Don't follow the 302 — we want to assert on the redirect itself.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// --- liveness probe goes through the full middleware chain ---
	resp := mustGet(t, client, (srv.URL + "/healthz"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz: status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Request-ID"); got == "" {
		t.Errorf("X-Request-ID header missing — RequestID middleware not in chain?")
	}
	if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY (SecurityHeaders not in chain?)", got)
	}
	resp.Body.Close()

	// --- embedded static index page ---
	resp = mustGet(t, client, (srv.URL + "/"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /: status = %d, want 200", resp.StatusCode)
	}
	body := mustRead(t, resp.Body)
	if !strings.Contains(body, "Tiny URL") {
		t.Errorf("/ body should embed the dashboard HTML, got first 80 chars: %q", body[:min(80, len(body))])
	}

	// --- create a short URL ---
	createBody, _ := json.Marshal(map[string]any{"url": "https://1.1.1.1/some/path"})
	createReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/shorten", bytes.NewReader(createBody))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("X-Requested-With", "XMLHttpRequest")
	resp = mustDo(t, client, (createReq))
	if resp.StatusCode != http.StatusCreated {
		body := mustRead(t, resp.Body)
		t.Fatalf("POST /api/shorten: status = %d, want 201, body=%s", resp.StatusCode, body)
	}
	var created struct {
		ShortCode  string `json:"short_code"`
		ShortURL   string `json:"short_url"`
		AdminToken string `json:"admin_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode shorten response: %v", err)
	}
	resp.Body.Close()
	if created.ShortCode == "" || created.AdminToken == "" {
		t.Fatalf("shorten response missing fields: %+v", created)
	}

	// --- POST without X-Requested-With must be rejected by CSRF middleware ---
	noXHRReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/shorten", bytes.NewReader(createBody))
	noXHRReq.Header.Set("Content-Type", "application/json")
	resp = mustDo(t, client, (noXHRReq))
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("POST /api/shorten without X-Requested-With: status = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()

	// --- redirect, increments click counter ---
	resp = mustGet(t, client, (srv.URL + "/" + created.ShortCode))
	if resp.StatusCode != http.StatusFound {
		t.Errorf("GET /%s: status = %d, want 302", created.ShortCode, resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "https://1.1.1.1/some/path" {
		t.Errorf("Location = %q, want https://1.1.1.1/some/path", loc)
	}
	resp.Body.Close()

	// Click is recorded asynchronously after RecordClick + atomic. Give the
	// handler a moment to settle before reading analytics back.
	time.Sleep(50 * time.Millisecond)

	// --- analytics requires owner token ---
	resp = mustGet(t, client, (srv.URL + "/api/analytics/" + created.ShortCode))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("analytics without token: status = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	analyticsReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/analytics/"+created.ShortCode, nil)
	analyticsReq.Header.Set("Authorization", "Bearer "+created.AdminToken)
	resp = mustDo(t, client, (analyticsReq))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("analytics with token: status = %d, want 200", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("analytics Cache-Control = %q, want no-store", cc)
	}
	var stats struct {
		ShortCode  string `json:"short_code"`
		ClickCount int    `json:"click_count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		t.Fatalf("decode analytics: %v", err)
	}
	resp.Body.Close()
	if stats.ShortCode != created.ShortCode {
		t.Errorf("analytics short_code = %q, want %q", stats.ShortCode, created.ShortCode)
	}
	if stats.ClickCount != 1 {
		t.Errorf("click_count = %d, want 1 (the redirect we sent)", stats.ClickCount)
	}

	// --- delete with the owner token ---
	delReq, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/url/"+created.ShortCode, nil)
	delReq.Header.Set("Authorization", "Bearer "+created.AdminToken)
	resp = mustDo(t, client, (delReq))
	if resp.StatusCode != http.StatusNoContent {
		body := mustRead(t, resp.Body)
		t.Errorf("DELETE: status = %d, want 204, body=%s", resp.StatusCode, body)
	}
	resp.Body.Close()

	// --- subsequent redirect should now 404 ---
	resp = mustGet(t, client, (srv.URL + "/" + created.ShortCode))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /%s after delete: status = %d, want 404", created.ShortCode, resp.StatusCode)
	}
	resp.Body.Close()
}

// TestEndToEndProbeBypassesRateLimit catches a class of regression that
// unit tests can't: probe paths must be mounted OUTSIDE the read rate
// limiter, and the favicon route must not fall through to GET /{code}.
func TestEndToEndProbeBypassesRateLimit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.Config{
		BaseURL:              "http://127.0.0.1",
		MaxExpirationMinutes: 525600,
		MaxBodyBytes:         4096,
		WriteRatePerMin:      1_000_000,
		ReadRatePerMin:       2, // intentionally tiny — probes must NOT eat from this bucket
		StorageBackend:       "memory",
	}
	handler, err := buildHandler(ctx, cfg, services.NewMemoryStore())
	if err != nil {
		t.Fatalf("buildHandler: %v", err)
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	client := &http.Client{Timeout: 2 * time.Second}

	// 10 healthz hits against a 2/min limit. All must succeed.
	for i := 0; i < 10; i++ {
		resp := mustGet(t, client, (srv.URL + "/healthz"))
		if resp.StatusCode != http.StatusOK {
			t.Errorf("healthz #%d: status = %d, want 200 (probe should bypass rate limiter)", i+1, resp.StatusCode)
		}
		resp.Body.Close()
	}

	// /favicon.ico should also bypass.
	resp := mustGet(t, client, (srv.URL + "/favicon.ico"))
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("/favicon.ico: status = %d, want 204", resp.StatusCode)
	}
	resp.Body.Close()
}

// --- helpers ---------------------------------------------------------

func mustGet(t *testing.T, c *http.Client, url string) *http.Response {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

func mustDo(t *testing.T, c *http.Client, req *http.Request) *http.Response {
	t.Helper()
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	return resp
}

func mustRead(t *testing.T, body io.ReadCloser) string {
	t.Helper()
	defer body.Close()
	b, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
