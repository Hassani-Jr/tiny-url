package middleware

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Limiter is a per-IP fixed-window rate limiter. Buckets are kept in a
// sync.Map and pruned by a background janitor so memory usage stays bounded
// even under high-cardinality client traffic (e.g. scanners cycling source IPs).
type Limiter struct {
	rate       int
	window     time.Duration
	trustProxy bool
	buckets    sync.Map // map[string]*bucket
}

type bucket struct {
	mu      sync.Mutex
	count   int
	resetAt time.Time
}

// NewLimiter constructs a Limiter and starts a janitor goroutine bound to ctx.
// The janitor exits when ctx is cancelled, which is how graceful shutdown
// avoids leaking the goroutine.
func NewLimiter(ctx context.Context, rate int, window time.Duration, trustProxy bool) *Limiter {
	l := &Limiter{
		rate:       rate,
		window:     window,
		trustProxy: trustProxy,
	}
	go l.janitor(ctx)
	return l
}

// Middleware returns an http.Handler wrapper that enforces the rate limit.
// On limit breach the response is 429 with a Retry-After header.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ClientIP(r, l.trustProxy)
		now := time.Now()

		v, _ := l.buckets.LoadOrStore(ip, &bucket{resetAt: now.Add(l.window)})
		b := v.(*bucket)

		b.mu.Lock()
		if now.After(b.resetAt) {
			b.count = 0
			b.resetAt = now.Add(l.window)
		}
		b.count++
		exceeded := b.count > l.rate
		retryAfter := int(time.Until(b.resetAt).Seconds()) + 1
		b.mu.Unlock()

		if exceeded {
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (l *Limiter) janitor(ctx context.Context) {
	t := time.NewTicker(l.window * 2)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			l.buckets.Range(func(k, v any) bool {
				b := v.(*bucket)
				b.mu.Lock()
				stale := now.After(b.resetAt)
				b.mu.Unlock()
				if stale {
					l.buckets.Delete(k)
				}
				return true
			})
		}
	}
}

// ClientIP extracts the client's IP address from the request, optionally
// honouring X-Forwarded-For when trustProxy is true. Reads the rightmost
// non-spoofable XFF entry; see the comment inside for the threat model.
func ClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		// Use the RIGHTMOST non-empty value of X-Forwarded-For. The
		// rightmost entry is appended by the operator's own trusted proxy
		// and is the only element we can vouch for. The leftmost entries
		// are attacker-controlled — a client can prepend arbitrary IPs to
		// rotate the rate-limit bucket key on every request and bypass the
		// limiter entirely. This deployment assumes a single trusted hop
		// in front of the Go process; multi-hop topologies need a more
		// sophisticated trust list.
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				ip := strings.TrimSpace(parts[i])
				if ip == "" {
					continue
				}
				// Require a parseable IP. A malicious client sending
				// long arbitrary strings could otherwise inflate the
				// bucket map's cardinality and pin memory until the
				// janitor catches up.
				if net.ParseIP(ip) == nil {
					continue
				}
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
