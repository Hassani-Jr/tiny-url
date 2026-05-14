package services

import (
	"context"
	"errors"
	"sort"
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

	// API key CRUD. Distinct from URL CRUD because keys have their own
	// lifecycle and the URL-side authorization path may resolve a key
	// hash → ID independently from URL lookups.
	//
	// CreateAPIKey inserts a fresh key and returns its assigned ID + a
	// fully-populated model (CreatedAt, etc.). The store hashes the
	// token before persisting; the caller never sees the stored bytes.
	CreateAPIKey(label string, tokenHash []byte) (*models.APIKey, error)
	// LookupAPIKey finds the key whose token hash matches the supplied
	// bytes. Returns ErrNotFound if no key matches. Also updates
	// last_used_at as a side effect — best-effort; a write failure here
	// is logged but does not fail the lookup.
	LookupAPIKey(tokenHash []byte) (*models.APIKey, error)
	// GetAPIKey fetches by ID; used after a successful auth to populate
	// PATCH/DELETE response bodies without rehashing the token.
	GetAPIKey(id int64) (*models.APIKey, error)
	// DeleteAPIKey removes the key. URLs that referenced it via
	// api_key_id are NOT deleted; the column is cleared so the per-URL
	// admin token remains the only credential.
	DeleteAPIKey(id int64) error
	// UpdateAPIKeyLabel changes the label without touching the hash.
	UpdateAPIKeyLabel(id int64, label string) error
	// ListURLsByAPIKey returns the URLs whose api_key_id == id, newest
	// first, paginated. Used by GET /api/urls.
	ListURLsByAPIKey(id int64, limit, offset int) ([]*models.URLMapping, error)

	// LogAudit records a state-changing action. Best-effort at the
	// caller — the handler logs and proceeds if this returns an error
	// rather than failing the user-visible operation just because the
	// audit row didn't land.
	LogAudit(event models.AuditEvent) error
	// RecentAuditEvents returns events newest-first, paginated. Used
	// by the operator-gated GET /api/audit endpoint.
	RecentAuditEvents(limit, offset int) ([]models.AuditEvent, error)
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
	// WebhookURL / WebhookSecret are set as a pair when adding or rotating
	// a webhook; ClearWebhook drops both. Setting either separately would
	// leave the row in an inconsistent state, so the handler always passes
	// both or neither.
	WebhookURL    *string
	WebhookSecret []byte
	ClearWebhook  bool
	// APIKeyID transfers (or clears, with 0) ownership of the URL to the
	// given API key. Pointer because 0 means "clear" — distinguishing
	// that from "leave alone" needs the explicit-nil convention.
	APIKeyID *int64
	// Preview fields are written only by the async Unfurler service.
	// The PATCH handler intentionally doesn't expose these to callers;
	// the API is "system-only" so a third party can't poison the
	// dashboard's preview cards. Setting any of these implies an
	// unfurl attempt completed, so SetPreviewFetched stamps the row.
	PreviewTitle       *string
	PreviewImage       *string
	PreviewDescription *string
	SetPreviewFetched  bool // when true, PreviewFetchedAt is stamped to now
	// Destinations replaces the entire routing pool. nil = leave
	// alone; non-nil (even empty) = replace, where an empty slice
	// reverts the URL to single-destination mode (uses OriginalURL).
	Destinations *[]models.Destination
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

	// API key state. nextKeyID is bumped on every CreateAPIKey so IDs
	// match the SQLite AUTOINCREMENT contract (monotonic, never reused).
	apiKeys   map[int64]*models.APIKey
	nextKeyID int64

	// Audit log state. memoryAuditCap caps the in-memory ring so a
	// long-running install can't OOM the process — older events are
	// dropped FIFO. SQLite + Postgres use time-based retention via the
	// cleanup goroutine.
	audit       []models.AuditEvent
	nextAuditID int64
}

// memoryAuditCap bounds the in-memory audit ring. Picked to keep the
// memory footprint negligible (a few KB at most) while still giving
// operators a useful recent history before old events roll off.
const memoryAuditCap = 1000

// NewMemoryStore creates an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		urls:    make(map[string]*models.URLMapping),
		events:  make(map[string][]models.ClickEvent),
		apiKeys: make(map[int64]*models.APIKey),
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

// Get returns a SNAPSHOT of the URL mapping — never the canonical
// pointer held in the map. The copy is made under the read lock so a
// concurrent Update (Unfurler, PATCH, RotateToken, …) cannot tear the
// struct fields the caller reads after return.
//
// The slice fields (Tags, Destinations, PasswordHash, PasswordSalt,
// WebhookSecret, OwnerTokenHash) share their underlying array with
// the stored mapping. That's safe because every Update path REPLACES
// the slice header instead of mutating the contents — readers that
// captured the old header continue to see consistent data.
//
// ClickCount is a value field; readers get a frozen point-in-time
// count. The atomic increments in RecordClick mutate the canonical
// stored pointer, not the snapshot, so subsequent calls to Get see a
// newer value. This trade-off is fine because every consumer reads
// the count via atomic.LoadInt64(&snapshot.ClickCount) and treats
// the result as advisory anyway.
func (s *MemoryStore) Get(code string) (*models.URLMapping, error) {
	s.mu.RLock()
	m, ok := s.urls[code]
	if !ok {
		s.mu.RUnlock()
		return nil, ErrNotFound
	}
	snap := *m
	s.mu.RUnlock()
	if snap.ExpiresAt != nil && time.Now().After(*snap.ExpiresAt) {
		return nil, ErrExpired
	}
	return &snap, nil
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
	switch {
	case f.ClearWebhook:
		m.WebhookURL = ""
		m.WebhookSecret = nil
	case f.WebhookURL != nil:
		m.WebhookURL = *f.WebhookURL
		if f.WebhookSecret != nil {
			m.WebhookSecret = append([]byte(nil), f.WebhookSecret...)
		}
	}
	if f.APIKeyID != nil {
		m.APIKeyID = *f.APIKeyID
	}
	if f.PreviewTitle != nil {
		m.PreviewTitle = *f.PreviewTitle
	}
	if f.PreviewImage != nil {
		m.PreviewImage = *f.PreviewImage
	}
	if f.PreviewDescription != nil {
		m.PreviewDescription = *f.PreviewDescription
	}
	if f.SetPreviewFetched {
		now := time.Now()
		m.PreviewFetchedAt = &now
	}
	if f.Destinations != nil {
		// Copy so the caller's slice can't mutate state outside the lock.
		m.Destinations = append([]models.Destination(nil), (*f.Destinations)...)
	}
	return nil
}

// CreateAPIKey inserts a new API key. ID is auto-assigned by the
// monotonic counter; CreatedAt is stamped server-side so the caller
// can't backdate.
func (s *MemoryStore) CreateAPIKey(label string, tokenHash []byte) (*models.APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextKeyID++
	k := &models.APIKey{
		ID:        s.nextKeyID,
		TokenHash: append([]byte(nil), tokenHash...),
		Label:     label,
		CreatedAt: time.Now(),
	}
	s.apiKeys[k.ID] = k
	return k, nil
}

// LookupAPIKey walks the map to find a hash match. Linear in the key
// count; the typical install has at most a handful of keys so this is
// fine. SQLite uses an index for the same query at scale.
func (s *MemoryStore) LookupAPIKey(tokenHash []byte) (*models.APIKey, error) {
	s.mu.Lock() // write lock — we update last_used_at on hit
	defer s.mu.Unlock()
	for _, k := range s.apiKeys {
		if bytesEqualConstTime(k.TokenHash, tokenHash) {
			now := time.Now()
			k.LastUsedAt = &now
			return k, nil
		}
	}
	return nil, ErrNotFound
}

// bytesEqualConstTime is a minimal constant-time byte compare. Avoids
// pulling crypto/subtle into the storage layer; the inputs are
// 32-byte SHA-256 outputs so the timing leak window is microscopic
// anyway, but constant-time keeps the property crisp.
func bytesEqualConstTime(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func (s *MemoryStore) GetAPIKey(id int64) (*models.APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.apiKeys[id]
	if !ok {
		return nil, ErrNotFound
	}
	return k, nil
}

func (s *MemoryStore) DeleteAPIKey(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.apiKeys[id]; !ok {
		return ErrNotFound
	}
	delete(s.apiKeys, id)
	// Clear api_key_id on any URLs that referenced this key — the
	// per-URL admin token remains a valid credential, so the URLs are
	// not orphaned, just disassociated from the deleted key.
	for _, u := range s.urls {
		if u.APIKeyID == id {
			u.APIKeyID = 0
		}
	}
	return nil
}

func (s *MemoryStore) UpdateAPIKeyLabel(id int64, label string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.apiKeys[id]
	if !ok {
		return ErrNotFound
	}
	k.Label = label
	return nil
}

// ListURLsByAPIKey returns URLs whose api_key_id == id, newest first
// (by CreatedAt). Pagination is via limit/offset; limit<=0 falls back
// to 50.
func (s *MemoryStore) ListURLsByAPIKey(id int64, limit, offset int) ([]*models.URLMapping, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 {
		limit = 50
	}
	var matched []*models.URLMapping
	for _, u := range s.urls {
		if u.APIKeyID == id {
			matched = append(matched, u)
		}
	}
	// Newest first.
	sortByCreatedAtDesc(matched)
	if offset < 0 {
		offset = 0
	}
	if offset >= len(matched) {
		return []*models.URLMapping{}, nil
	}
	end := offset + limit
	if end > len(matched) {
		end = len(matched)
	}
	return matched[offset:end], nil
}

// sortByCreatedAtDesc sorts in place by CreatedAt descending. Standard
// sort.Slice — the matched list can grow with the user's URL count, so
// we want O(N log N).
func sortByCreatedAtDesc(list []*models.URLMapping) {
	sort.Slice(list, func(i, j int) bool {
		return list[i].CreatedAt.After(list[j].CreatedAt)
	})
}

// LogAudit records an event in the in-memory ring. The ring is bounded
// (memoryAuditCap) — older entries roll off FIFO once the cap is hit.
// Synchronous and best-effort at the caller: handlers log + proceed
// rather than failing the user-visible op if this returns an error.
func (s *MemoryStore) LogAudit(ev models.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextAuditID++
	ev.ID = s.nextAuditID
	if ev.At.IsZero() {
		ev.At = time.Now()
	}
	if len(s.audit) >= memoryAuditCap {
		// Drop oldest by sliding the window. copy+truncate is the
		// simplest implementation; a true ring would save the copy
		// but the cap is small enough that it doesn't matter.
		copy(s.audit, s.audit[1:])
		s.audit = s.audit[:len(s.audit)-1]
	}
	s.audit = append(s.audit, ev)
	return nil
}

// RecentAuditEvents returns events newest-first with limit/offset
// pagination. limit<=0 falls back to 50.
func (s *MemoryStore) RecentAuditEvents(limit, offset int) ([]models.AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	// Walk newest-first by iterating backwards.
	total := len(s.audit)
	if offset >= total {
		return []models.AuditEvent{}, nil
	}
	end := total - offset
	start := end - limit
	if start < 0 {
		start = 0
	}
	out := make([]models.AuditEvent, 0, end-start)
	for i := end - 1; i >= start; i-- {
		out = append(out, s.audit[i])
	}
	return out, nil
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
