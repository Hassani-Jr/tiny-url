package services

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
	"tiny-url/models"
)

var (
	ErrNotFound     = errors.New("short code not found")
	ErrExpired      = errors.New("URL has expired")
	ErrCodeConflict = errors.New("short code already exists")
)

// Store is the persistence contract for URL mappings. Implementations may be
// fully in-memory or backed by a durable store; handlers depend only on this
// interface so the backend is swappable at runtime via STORAGE_BACKEND.
type Store interface {
	Set(code string, m *models.URLMapping) error
	Get(code string) (*models.URLMapping, error)
	Delete(code string) error
	Exists(code string) bool
	// RecordClick atomically increments click_count, updates last_accessed
	// to ev.At, and appends ev to the per-code event log. The "atomic"
	// guarantee matters because the click counter and event log are
	// queried independently — if they could drift (one write succeeds
	// while the other fails), an analytics consumer would see counts that
	// don't match `len(events)` and have no way to reconcile.
	//
	// Best-effort at the handler layer: the redirect handler logs an
	// error and proceeds rather than failing the user's redirect over a
	// missed analytics row. Returns ErrNotFound if the code is unknown.
	RecordClick(code string, ev models.ClickEvent) error
	// RecentClicks returns up to limit events for code, newest first. Used
	// by /api/analytics/{code}/clicks. limit<=0 implies the implementation
	// default (50).
	RecentClicks(code string, limit int) ([]models.ClickEvent, error)
	// Update overwrites the mutable fields of an existing mapping. Every
	// "value" pointer is "leave alone if nil"; the explicit Clear* flags
	// disambiguate "set to zero" from "leave alone" for fields where the
	// zero value is meaningful (clearing expiration, clearing the password).
	// Immutable fields (CreatedAt, OwnerTokenHash, ClickCount) are preserved.
	// Returns ErrNotFound if the code is unknown.
	Update(code string, fields UpdateFields) error
	// ClicksByBucket returns click counts grouped into buckets of `bucket`
	// duration ending at `until` and reaching back `count` buckets. The
	// oldest bucket is at index 0; the newest at index count-1. Used by the
	// time-series analytics endpoint to render a sparkline of activity over
	// arbitrary windows without paging through raw events.
	ClicksByBucket(code string, until time.Time, bucket time.Duration, count int) ([]int64, error)
	// RotateToken atomically replaces the owner-token hash for a code.
	// The handler verifies the OLD token first; this method assumes that
	// authorisation has already happened. Used to rotate a possibly-leaked
	// admin token without re-creating the URL. Returns ErrNotFound if the
	// code is unknown.
	RotateToken(code string, newHash []byte) error
	// Ping verifies that the backend is reachable. Used by /readyz so a
	// liveness check (/healthz) can stay cheap while a readiness check
	// surfaces backend outages to the load balancer.
	Ping(ctx context.Context) error
	StartCleanupRoutine(ctx context.Context, interval time.Duration)
	Close() error
}

// UpdateFields is the patch payload passed to Store.Update. Pointer fields
// distinguish "field not present in the PATCH body" (nil) from "present
// and set to its zero value" (non-nil pointer to zero). Tags is special-
// cased: a nil slice means "leave alone" while a non-nil empty slice means
// "clear all tags". The Clear* booleans cover fields where the zero value
// has a domain-specific meaning (expiration removal, password removal).
type UpdateFields struct {
	OriginalURL     *string
	ExpiresAt       *time.Time
	ClearExpiration bool
	Tags            *[]string // nil = leave alone; non-nil = replace whole list
	MaxClicks       *int64
	PasswordHash    []byte
	PasswordSalt    []byte
	ClearPassword   bool
}

// memoryClickCapPerCode bounds the in-memory event log per short code so a
// hot link can't OOM the process. Older events are dropped FIFO; the SQLite
// backend uses time-based retention instead since disk is cheap.
const memoryClickCapPerCode = 1000

// MemoryStore is an in-memory Store. Loses data on restart; intended for
// development and as the default zero-config backend.
type MemoryStore struct {
	urls   map[string]*models.URLMapping
	events map[string][]models.ClickEvent // per-code FIFO ring, capped at memoryClickCapPerCode
	mu     sync.RWMutex
}

// NewMemoryStore creates an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		urls:   make(map[string]*models.URLMapping),
		events: make(map[string][]models.ClickEvent),
	}
}

// Set inserts a fresh mapping. Returns ErrCodeConflict if the code already
// exists — Set is *not* an upsert. Callers that need to overwrite must Delete
// first. The conflict-aware behavior closes the Exists/Set TOCTOU race in the
// shorten handler so that a parallel claim of the same custom alias cannot
// silently clobber the first writer's owner-token hash.
func (s *MemoryStore) Set(code string, m *models.URLMapping) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.urls[code]; exists {
		return ErrCodeConflict
	}
	s.urls[code] = m
	return nil
}

func (s *MemoryStore) Get(code string) (*models.URLMapping, error) {
	s.mu.RLock()
	m, ok := s.urls[code]
	s.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	if m.ExpiresAt != nil && time.Now().After(*m.ExpiresAt) {
		return nil, ErrExpired
	}
	return m, nil
}

// Delete removes a mapping (and its event log) atomically. Returns
// ErrNotFound if the code is unknown so callers can distinguish "already
// gone" from "never existed" — the DELETE handler reports both as 204 to
// the client but we want the difference in the store layer for tests and
// future audit logging.
func (s *MemoryStore) Delete(code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.urls[code]; !ok {
		return ErrNotFound
	}
	delete(s.urls, code)
	delete(s.events, code)
	return nil
}

// RecentClicks returns up to limit events for code, newest first.
func (s *MemoryStore) RecentClicks(code string, limit int) ([]models.ClickEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.urls[code]; !ok {
		return nil, ErrNotFound
	}
	list := s.events[code]
	if limit <= 0 {
		limit = 50
	}
	if limit > len(list) {
		limit = len(list)
	}
	out := make([]models.ClickEvent, limit)
	for i := 0; i < limit; i++ {
		out[i] = list[len(list)-1-i]
	}
	return out, nil
}

// RotateToken replaces the owner-token hash. Mutates in-place under the
// write lock so the analytics handler's atomic read of ClickCount is
// unaffected.
func (s *MemoryStore) RotateToken(code string, newHash []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.urls[code]
	if !ok {
		return ErrNotFound
	}
	// Take a copy so we don't share the caller's slice backing array.
	m.OwnerTokenHash = append([]byte(nil), newHash...)
	return nil
}

// Update overwrites mutable fields. See UpdateFields for the contract of
// each pointer / Clear* combination.
func (s *MemoryStore) Update(code string, f UpdateFields) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.urls[code]
	if !ok {
		return ErrNotFound
	}
	if f.OriginalURL != nil {
		m.OriginalURL = *f.OriginalURL
	}
	switch {
	case f.ClearExpiration:
		m.ExpiresAt = nil
	case f.ExpiresAt != nil:
		t := *f.ExpiresAt
		m.ExpiresAt = &t
	}
	if f.Tags != nil {
		// Copy so the caller's slice can't mutate state outside the lock.
		m.Tags = append([]string(nil), (*f.Tags)...)
	}
	if f.MaxClicks != nil {
		m.MaxClicks = *f.MaxClicks
	}
	switch {
	case f.ClearPassword:
		m.PasswordHash = nil
		m.PasswordSalt = nil
	case f.PasswordHash != nil:
		m.PasswordHash = append([]byte(nil), f.PasswordHash...)
		m.PasswordSalt = append([]byte(nil), f.PasswordSalt...)
	}
	return nil
}

// ClicksByBucket walks the in-memory event log and aggregates into
// `count` buckets of `bucket` duration ending at `until`. The slice is
// returned oldest-first.
func (s *MemoryStore) ClicksByBucket(code string, until time.Time, bucket time.Duration, count int) ([]int64, error) {
	if count <= 0 || bucket <= 0 {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.urls[code]; !ok {
		return nil, ErrNotFound
	}
	out := make([]int64, count)
	windowStart := until.Add(-time.Duration(count) * bucket)
	for _, ev := range s.events[code] {
		if ev.At.Before(windowStart) || !ev.At.Before(until) {
			continue
		}
		idx := int(ev.At.Sub(windowStart) / bucket)
		if idx >= 0 && idx < count {
			out[idx]++
		}
	}
	return out, nil
}

// Ping for the in-memory store is always healthy — the data structure is
// the same goroutine and the same heap, there is nothing to ping.
func (s *MemoryStore) Ping(_ context.Context) error { return nil }

func (s *MemoryStore) Exists(code string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.urls[code]
	return ok
}

// RecordClick increments the counter, updates last-accessed, and appends
// to the per-code ring under a single mutex hold so analytics readers
// never observe a half-written click. The atomic.AddInt64 is for the
// out-of-lock reader in the analytics handler — see the comment on
// URLMapping.ClickCount.
func (s *MemoryStore) RecordClick(code string, ev models.ClickEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.urls[code]
	if !ok {
		return ErrNotFound
	}
	atomic.AddInt64(&m.ClickCount, 1)
	t := ev.At
	m.LastAccessed = &t
	list := s.events[code]
	if len(list) >= memoryClickCapPerCode {
		// Drop oldest. copy+slice is the simplest path; a true ring buffer
		// would save the copy but adds bookkeeping that is hard to justify
		// at this scale.
		copy(list, list[1:])
		list = list[:len(list)-1]
	}
	s.events[code] = append(list, ev)
	return nil
}

func (s *MemoryStore) StartCleanupRoutine(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.cleanupExpired()
			}
		}
	}()
}

func (s *MemoryStore) Close() error { return nil }

func (s *MemoryStore) cleanupExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for code, m := range s.urls {
		if m.ExpiresAt != nil && now.After(*m.ExpiresAt) {
			delete(s.urls, code)
		}
	}
}
