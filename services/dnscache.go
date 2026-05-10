package services

import (
	"sync"
	"time"
)

// DNSCache memoises ValidateHostAtRuntime results so a hot short URL
// doesn't re-resolve on every redirect. The intended TTL is short
// (seconds, not minutes) because the whole point of the redirect-time
// re-check is catching DNS rebinding — too-long a cache TTL would defeat
// it. With TTL=5s a rebound host is blocked within 5 seconds of the DNS
// flip, which matches the threat model's "block within seconds" target.
//
// Both successful (nil) and failing (non-nil) results are cached. A
// hostname that's reliably failing doesn't need to be re-resolved every
// click either — caching the failure for the same window prevents the
// DNS resolver from being a DDoS amplifier when a popular short URL
// points at a non-resolving host.
type DNSCache struct {
	ttl  time.Duration
	cap  int
	mu   sync.Mutex
	data map[string]dnsCacheEntry
}

type dnsCacheEntry struct {
	err     error
	expires time.Time
}

func NewDNSCache(ttl time.Duration, capacity int) *DNSCache {
	if ttl <= 0 {
		ttl = 5 * time.Second
	}
	if capacity <= 0 {
		capacity = 1024
	}
	return &DNSCache{
		ttl:  ttl,
		cap:  capacity,
		data: make(map[string]dnsCacheEntry, capacity),
	}
}

// ValidateHost returns the cached validation result for host, falling
// through to ValidateHostAtRuntime on miss or expiry. Receiver-nil-safe
// so callers (the redirect handler) can be wired with or without the
// cache uniformly.
func (c *DNSCache) ValidateHost(host string) error {
	if c == nil {
		return ValidateHostAtRuntime(host)
	}
	now := time.Now()

	c.mu.Lock()
	if e, ok := c.data[host]; ok && now.Before(e.expires) {
		c.mu.Unlock()
		return e.err
	}
	c.mu.Unlock()

	// Resolve outside the lock — ValidateHostAtRuntime may take seconds
	// (DNS timeout) and we don't want to block readers/writers for other
	// hosts while one slow lookup is in flight.
	err := ValidateHostAtRuntime(host)

	c.mu.Lock()
	c.evictIfFullLocked(now)
	c.data[host] = dnsCacheEntry{err: err, expires: now.Add(c.ttl)}
	c.mu.Unlock()
	return err
}

// evictIfFullLocked is called with c.mu held. When the map hits the cap,
// drop expired entries first; if still full, drop everything. Simple
// eviction beats LRU at this scale — cap is ~1k entries in practice and
// a full clear costs microseconds.
func (c *DNSCache) evictIfFullLocked(now time.Time) {
	if len(c.data) < c.cap {
		return
	}
	for k, v := range c.data {
		if now.After(v.expires) {
			delete(c.data, k)
		}
	}
	if len(c.data) >= c.cap {
		// All entries still in TTL. Pragmatic: clear the slate. The
		// alternative (reject new inserts) would block validation of
		// new hosts; clearing forces re-resolution for everyone, which
		// is the correct fail-mode (validate, don't skip).
		c.data = make(map[string]dnsCacheEntry, c.cap)
	}
}

// Size is exposed for tests and diagnostics.
func (c *DNSCache) Size() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.data)
}
