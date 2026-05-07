package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestRateLimiter(t *testing.T) {
	t.Run("allows requests under limit", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		limiter := NewLimiter(ctx, 10, time.Minute, false)
		handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// Make 10 requests (should all succeed)
		for i := 0; i < 10; i++ {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = "127.0.0.1:12345"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Request %d: status = %d, want 200", i+1, w.Code)
			}
		}
	})

	t.Run("blocks requests over limit", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		limiter := NewLimiter(ctx, 5, time.Minute, false)
		handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// Make 6 requests from same IP
		for i := 0; i < 6; i++ {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if i < 5 {
				if w.Code != http.StatusOK {
					t.Errorf("Request %d: status = %d, want 200", i+1, w.Code)
				}
			} else {
				// 6th request should be rate limited
				if w.Code != http.StatusTooManyRequests {
					t.Errorf("Request %d: status = %d, want 429", i+1, w.Code)
				}
			}
		}
	})

	t.Run("independent limits per IP", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		limiter := NewLimiter(ctx, 3, time.Minute, false)
		handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// IP1: make 3 requests
		for i := 0; i < 3; i++ {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = "10.0.0.1:12345"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("IP1 Request %d: status = %d, want 200", i+1, w.Code)
			}
		}

		// IP2: make 3 requests (should all succeed, independent from IP1)
		for i := 0; i < 3; i++ {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = "10.0.0.2:12345"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("IP2 Request %d: status = %d, want 200", i+1, w.Code)
			}
		}

		// IP1: 4th request should be rate limited
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusTooManyRequests {
			t.Errorf("IP1 Request 4: status = %d, want 429", w.Code)
		}

		// IP2: 4th request should also be rate limited
		req2 := httptest.NewRequest("GET", "/", nil)
		req2.RemoteAddr = "10.0.0.2:12345"
		w2 := httptest.NewRecorder()
		handler.ServeHTTP(w2, req2)

		if w2.Code != http.StatusTooManyRequests {
			t.Errorf("IP2 Request 4: status = %d, want 429", w2.Code)
		}
	})

	t.Run("retryafter header on rate limit", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		limiter := NewLimiter(ctx, 1, time.Minute, false)
		handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// Use up the 1 request
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "172.16.0.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// Next request should be rate limited
		req2 := httptest.NewRequest("GET", "/", nil)
		req2.RemoteAddr = "172.16.0.1:12345"
		w2 := httptest.NewRecorder()
		handler.ServeHTTP(w2, req2)

		if w2.Code != http.StatusTooManyRequests {
			t.Errorf("status = %d, want 429", w2.Code)
		}

		retryAfter := w2.Header().Get("Retry-After")
		if retryAfter == "" {
			t.Error("Retry-After header missing")
		}
	})

	t.Run("uses rightmost xff element to defeat spoofed prefix", func(t *testing.T) {
		// Regression test: a malicious client can prepend arbitrary IPs to
		// X-Forwarded-For. The trusted proxy appends its own observation
		// at the rightmost position, so that's the value we must key on.
		// Reading the leftmost element would let an attacker rotate the
		// bucket key on every request and bypass the rate limit entirely.
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		limiter := NewLimiter(ctx, 2, time.Minute, true)
		handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// Three requests, each with a *different* spoofed leftmost IP but
		// the same trusted-proxy IP at the rightmost position. After the
		// fix, all three count against the same bucket and the third
		// request must be rate-limited.
		spoofs := []string{
			"1.2.3.4, 198.51.100.7",
			"5.6.7.8, 198.51.100.7",
			"9.10.11.12, 198.51.100.7",
		}
		for i, xff := range spoofs {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("X-Forwarded-For", xff)
			req.RemoteAddr = "proxy.example.com:12345"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			want := http.StatusOK
			if i == 2 {
				want = http.StatusTooManyRequests
			}
			if w.Code != want {
				t.Errorf("Spoofed request %d (xff=%q): status = %d, want %d", i+1, xff, w.Code, want)
			}
		}
	})

	t.Run("non-IP xff value falls back to RemoteAddr", func(t *testing.T) {
		// When a malicious client sends a bogus XFF value (long arbitrary
		// string, not a real IP) we must not key the bucket on it — otherwise
		// each request rotates the key and bypasses the limit. The limiter
		// should fall through to the next valid element, or to RemoteAddr.
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		limiter := NewLimiter(ctx, 2, time.Minute, true)
		handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// Three requests with distinct garbage XFFs but the same RemoteAddr.
		// All three should key on RemoteAddr; the third is rate-limited.
		garbages := []string{"not-an-ip-1", "not-an-ip-2", "not-an-ip-3"}
		for i, g := range garbages {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("X-Forwarded-For", g)
			req.RemoteAddr = "203.0.113.99:5555"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			want := http.StatusOK
			if i == 2 {
				want = http.StatusTooManyRequests
			}
			if w.Code != want {
				t.Errorf("request %d (xff=%q): status = %d, want %d", i+1, g, w.Code, want)
			}
		}
	})

	t.Run("trusts x-forwarded-for when enabled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		limiter := NewLimiter(ctx, 2, time.Minute, true) // trustProxy=true
		handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// Make 2 requests with same X-Forwarded-For
		for i := 0; i < 2; i++ {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("X-Forwarded-For", "203.0.113.1")
			req.RemoteAddr = "proxy.example.com:12345"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Request %d: status = %d, want 200", i+1, w.Code)
			}
		}

		// 3rd request should be rate limited
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Forwarded-For", "203.0.113.1")
		req.RemoteAddr = "proxy.example.com:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusTooManyRequests {
			t.Errorf("Request 3: status = %d, want 429", w.Code)
		}
	})
}

func TestRateLimiterConcurrency(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	limiter := NewLimiter(ctx, 100, time.Minute, false)
	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Multiple goroutines making concurrent requests
	var wg sync.WaitGroup
	successCount := 0
	rateLimitedCount := 0
	mu := sync.Mutex{}

	for i := 0; i < 150; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = "192.168.1.100:12345"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			mu.Lock()
			if w.Code == http.StatusOK {
				successCount++
			} else if w.Code == http.StatusTooManyRequests {
				rateLimitedCount++
			}
			mu.Unlock()
		}()
	}

	wg.Wait()

	// Should have exactly 100 successes and 50 rate limits
	if successCount != 100 {
		t.Errorf("successCount = %d, want 100", successCount)
	}
	if rateLimitedCount != 50 {
		t.Errorf("rateLimitedCount = %d, want 50", rateLimitedCount)
	}
}

func TestRateLimiterWindowReset(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	window := 100 * time.Millisecond
	limiter := NewLimiter(ctx, 2, window, false)
	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Use up the 2 requests
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.20.30.40:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}

	// Next request should be rate limited
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.20.30.40:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Before window reset: status = %d, want 429", w.Code)
	}

	// Wait for window to reset
	time.Sleep(window + 50*time.Millisecond)

	// Request should succeed now
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "10.20.30.40:12345"
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("After window reset: status = %d, want 200", w2.Code)
	}
}

func TestRateLimiterCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	window := 50 * time.Millisecond
	limiter := NewLimiter(ctx, 10, window, false)

	// Make a request from an IP
	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.50:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Wait for cleanup (2 * window)
	time.Sleep(2*window + 100*time.Millisecond)

	// New request from same IP should not inherit old bucket
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "203.0.113.50:12345"
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (bucket should be cleaned up)", w2.Code)
	}
}
