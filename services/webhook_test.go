package services

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestWebhookDispatcherDelivery exercises the happy path end-to-end: a
// successful 2xx response increments `sent`, the body carries the
// expected payload, and the X-Tinyurl-Signature header verifies under
// the configured secret.
func TestWebhookDispatcherDelivery(t *testing.T) {
	var receivedBody []byte
	var receivedSig string
	var hits atomic.Int32
	done := make(chan struct{}, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		receivedBody, _ = io.ReadAll(r.Body)
		receivedSig = r.Header.Get("X-Tinyurl-Signature")
		w.WriteHeader(http.StatusOK)
		select {
		case done <- struct{}{}:
		default:
		}
	}))
	t.Cleanup(srv.Close)

	d := NewWebhookDispatcher(1, 8, 2*time.Second)
	d.hostValidator = func(string) error { return nil }
	t.Cleanup(d.Close)

	secret := []byte("test-secret")
	payload := []byte(`{"short_code":"abc","at":"2026-01-01T00:00:00Z"}`)
	if !d.Enqueue(WebhookEvent{
		Code: "abc", URL: srv.URL, Secret: secret, Payload: payload,
	}) {
		t.Fatal("Enqueue returned false")
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("webhook never delivered")
	}

	if hits.Load() != 1 {
		t.Errorf("hits = %d, want 1", hits.Load())
	}
	if string(receivedBody) != string(payload) {
		t.Errorf("body = %q, want %q", receivedBody, payload)
	}
	if !VerifyWebhookSignature(secret, payload, receivedSig) {
		t.Errorf("signature %q failed verification", receivedSig)
	}

	// Wait a moment for the worker's sent counter to tick (it's set after
	// the response handler returns).
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if s, _, _ := d.Stats(); s == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	s, f, drops := d.Stats()
	t.Errorf("stats = sent:%d failed:%d dropped:%d, want sent:1", s, f, drops)
}

// TestWebhookDispatcherRetryOn5xx asserts that the dispatcher retries
// after a 503 and eventually succeeds, with retries counted as a single
// "sent" (not three).
func TestWebhookDispatcherRetryOn5xx(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	d := NewWebhookDispatcher(1, 8, time.Second)
	d.hostValidator = func(string) error { return nil }
	t.Cleanup(d.Close)

	d.Enqueue(WebhookEvent{Code: "abc", URL: srv.URL, Secret: []byte("k"), Payload: []byte("{}")})

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s, _, _ := d.Stats(); s == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if hits.Load() < 2 {
		t.Errorf("hits = %d, want at least 2 (retry must happen)", hits.Load())
	}
	if s, f, _ := d.Stats(); s != 1 || f != 0 {
		t.Errorf("stats sent=%d failed=%d, want 1/0", s, f)
	}
}

// TestWebhookDispatcherNoRetryOn4xx asserts the dispatcher does NOT retry
// a 4xx — those are misconfigurations the receiver must fix, and
// retrying just wastes resources.
func TestWebhookDispatcherNoRetryOn4xx(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	d := NewWebhookDispatcher(1, 8, time.Second)
	d.hostValidator = func(string) error { return nil }
	t.Cleanup(d.Close)

	d.Enqueue(WebhookEvent{Code: "abc", URL: srv.URL, Secret: []byte("k"), Payload: []byte("{}")})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, f, _ := d.Stats(); f == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if h := hits.Load(); h != 1 {
		t.Errorf("hits = %d, want exactly 1 (no retry on 4xx)", h)
	}
}

// TestWebhookDispatcherDoesNotFollowRedirects ensures a 302 from the
// receiver does NOT cause us to re-issue against the redirect target —
// that would let a receiver bypass create-time SSRF by 302'ing to
// 127.0.0.1.
func TestWebhookDispatcherDoesNotFollowRedirects(t *testing.T) {
	var redirectedTo atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedTo.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(internal.Close)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", internal.URL)
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	d := NewWebhookDispatcher(1, 8, time.Second)
	d.hostValidator = func(string) error { return nil }
	t.Cleanup(d.Close)

	d.Enqueue(WebhookEvent{Code: "abc", URL: srv.URL, Secret: []byte("k"), Payload: []byte("{}")})

	time.Sleep(500 * time.Millisecond)
	if redirectedTo.Load() != 0 {
		t.Errorf("dispatcher followed a redirect (%d hits on internal server) — SSRF defence broken",
			redirectedTo.Load())
	}
}

// TestWebhookSignatureRoundTrip is a tiny algorithm sanity check: a
// manually-computed HMAC matches VerifyWebhookSignature's expectation.
func TestWebhookSignatureRoundTrip(t *testing.T) {
	secret := []byte("the-key")
	body := []byte(`{"x":1}`)
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !VerifyWebhookSignature(secret, body, expected) {
		t.Errorf("VerifyWebhookSignature rejected a correct signature")
	}
	if VerifyWebhookSignature(secret, body, "sha256=deadbeef") {
		t.Errorf("VerifyWebhookSignature accepted a wrong signature")
	}
	if VerifyWebhookSignature(secret, body, "md5=anything") {
		t.Errorf("VerifyWebhookSignature accepted an unsupported algorithm")
	}
}
