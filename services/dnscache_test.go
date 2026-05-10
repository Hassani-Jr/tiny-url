package services

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestDNSCacheNilSafe(t *testing.T) {
	// Receiver-nil-safe so handlers that don't pass a cache still work.
	var c *DNSCache
	// Use an IP literal so we don't make a real DNS query.
	if err := c.ValidateHost("1.1.1.1"); err != nil {
		t.Errorf("nil cache + valid host: err = %v, want nil", err)
	}
	if c.Size() != 0 {
		t.Errorf("nil cache Size() = %d, want 0", c.Size())
	}
}

func TestDNSCacheCachesSuccess(t *testing.T) {
	c := NewDNSCache(5*time.Second, 16)
	if err := c.ValidateHost("1.1.1.1"); err != nil {
		t.Fatalf("first call: err = %v, want nil", err)
	}
	if c.Size() != 1 {
		t.Errorf("Size after one entry = %d, want 1", c.Size())
	}
	// Second call should hit the cache. We can't directly observe the
	// "no DNS lookup" without a fake resolver, but we can at least assert
	// the result is consistent and the cache size doesn't grow.
	if err := c.ValidateHost("1.1.1.1"); err != nil {
		t.Errorf("cached call: err = %v, want nil", err)
	}
	if c.Size() != 1 {
		t.Errorf("Size after duplicate = %d, want still 1", c.Size())
	}
}

func TestDNSCacheCachesFailure(t *testing.T) {
	// 127.0.0.1 is a loopback IP — the validator returns a non-nil error.
	// Caching the failure means we don't re-validate every redirect.
	c := NewDNSCache(5*time.Second, 16)
	err1 := c.ValidateHost("127.0.0.1")
	if err1 == nil {
		t.Fatalf("expected loopback rejection, got nil")
	}
	err2 := c.ValidateHost("127.0.0.1")
	if !errors.Is(err2, ErrPrivateAddress) {
		t.Errorf("cached failure should still wrap ErrPrivateAddress, got %v", err2)
	}
}

func TestDNSCacheTTLExpiry(t *testing.T) {
	c := NewDNSCache(50*time.Millisecond, 16)
	_ = c.ValidateHost("1.1.1.1")
	if c.Size() != 1 {
		t.Fatalf("Size after first call = %d, want 1", c.Size())
	}
	time.Sleep(120 * time.Millisecond)
	// Touching the same host after expiry triggers a fresh lookup, which
	// re-populates the cache. Size stays 1 (overwrite) but the entry's
	// expiry has been pushed forward.
	_ = c.ValidateHost("1.1.1.1")
	if c.Size() != 1 {
		t.Errorf("Size after re-lookup = %d, want 1", c.Size())
	}
}

func TestDNSCacheEviction(t *testing.T) {
	// Cap of 4. Insert 4 expired entries directly, then a new lookup —
	// the expired ones should be cleared first to make room.
	c := NewDNSCache(time.Hour, 4)
	now := time.Now()
	c.mu.Lock()
	for _, k := range []string{"a", "b", "c", "d"} {
		c.data[k] = dnsCacheEntry{err: nil, expires: now.Add(-time.Second)}
	}
	c.mu.Unlock()
	if c.Size() != 4 {
		t.Fatalf("setup Size = %d, want 4", c.Size())
	}
	_ = c.ValidateHost("1.1.1.1")
	// The 4 expired entries should have been swept; we now have 1 fresh.
	if c.Size() != 1 {
		t.Errorf("Size after eviction = %d, want 1 (4 expired swept, 1 fresh added)", c.Size())
	}
}

func TestDNSCacheConcurrent(t *testing.T) {
	// Smoke test for races. Run with -race for real coverage.
	c := NewDNSCache(time.Second, 64)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = c.ValidateHost("1.1.1.1")
			}
		}()
	}
	wg.Wait()
}
