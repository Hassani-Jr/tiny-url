package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
	"tiny-url/models"

	_ "modernc.org/sqlite"
)

// SQLiteStore is a durable Store backed by SQLite via the pure-Go
// modernc.org/sqlite driver (no CGO). Times are persisted as Unix
// nanoseconds; nullable timestamps and the owner-token hash use
// sql.Null* / BLOB columns.
type SQLiteStore struct {
	db             *sql.DB
	clickRetention time.Duration // 0 disables retention pruning
	// cleanupWG tracks the StartCleanupRoutine goroutine so Close() can
	// wait for it before tearing down the DB. Without this join, a test
	// that defers `cancel()` and `store.Close()` would race the cleanup
	// goroutine — it might still be running an Exec when the temp dir
	// gets RemoveAll'd, leaving files behind and failing the test on
	// Linux with "directory not empty".
	cleanupWG sync.WaitGroup
}

const sqliteSchema = `
CREATE TABLE IF NOT EXISTS urls (
    short_code        TEXT PRIMARY KEY,
    original_url      TEXT NOT NULL,
    created_at        INTEGER NOT NULL,
    expires_at        INTEGER,
    click_count       INTEGER NOT NULL DEFAULT 0,
    last_accessed     INTEGER,
    owner_token_hash  BLOB
);
CREATE INDEX IF NOT EXISTS idx_urls_expires_at ON urls(expires_at)
    WHERE expires_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS click_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    short_code  TEXT NOT NULL,
    clicked_at  INTEGER NOT NULL,
    ip_hash     TEXT,
    referer     TEXT,
    ua_class    TEXT,
    FOREIGN KEY (short_code) REFERENCES urls(short_code) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_click_events_code_time
    ON click_events(short_code, clicked_at DESC);
`

// addedColumns is the list of columns that didn't exist in the v1 schema
// and must be present for the current code to operate. SQLite has no
// IF NOT EXISTS clause for ADD COLUMN before 3.35, but we tolerate a
// "duplicate column" error from the driver as a no-op so re-running on an
// already-migrated database is harmless.
//
// Each entry is run as a standalone ALTER TABLE; SQLite forbids multiple
// ADD COLUMNs in one statement.
var addedColumns = []string{
	`ALTER TABLE urls ADD COLUMN tags TEXT`,             // JSON array; NULL == no tags
	`ALTER TABLE urls ADD COLUMN max_clicks INTEGER`,    // 0/NULL == unlimited
	`ALTER TABLE urls ADD COLUMN password_hash BLOB`,    // NULL == no password
	`ALTER TABLE urls ADD COLUMN password_salt BLOB`,    // paired with password_hash
}

// NewSQLiteStore opens (or creates) a SQLite database at path and applies
// the schema. WAL journaling and a generous busy_timeout reduce contention
// when the cleanup goroutine and a request handler write concurrently.
// Foreign keys are explicitly enabled so the click_events ON DELETE CASCADE
// actually fires when a URL is deleted.
func NewSQLiteStore(path string) (*SQLiteStore, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite open: %w", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite ping: %w", err)
	}
	if _, err := db.Exec(sqliteSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite schema: %w", err)
	}
	for _, stmt := range addedColumns {
		if _, err := db.Exec(stmt); err != nil && !isDuplicateColumnErr(err) {
			_ = db.Close()
			return nil, fmt.Errorf("sqlite migrate %q: %w", stmt, err)
		}
	}
	return &SQLiteStore{db: db}, nil
}

// isDuplicateColumnErr matches the modernc.org/sqlite error message emitted
// when ALTER TABLE ADD COLUMN runs against a column that already exists.
// There's no sentinel error to compare against; the driver reflects the
// underlying SQLITE_ERROR string verbatim, so substring match is the
// documented approach for this driver.
func isDuplicateColumnErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate column name")
}

// SetClickRetention configures how long click_events rows are kept by the
// cleanup goroutine. Zero (the default) disables retention pruning so old
// events stay forever — fine for low-volume deployments and avoids dropping
// data behind the operator's back. Operators set this from
// CLICK_RETENTION_DAYS to bound the table on long-running services.
func (s *SQLiteStore) SetClickRetention(d time.Duration) {
	s.clickRetention = d
}

// Close blocks until the cleanup goroutine (if any) has exited, then closes
// the underlying DB. Callers MUST cancel the context passed to
// StartCleanupRoutine before invoking Close, otherwise this will block
// forever waiting for the goroutine that's still polling.
//
// The join matters because the cleanup goroutine holds a connection
// reference and may have files open inside the SQLite WAL; closing the DB
// while it's mid-Exec leaves the WAL/SHM sidecars in a state that confuses
// downstream cleanup (notably t.TempDir's RemoveAll on Linux CI).
func (s *SQLiteStore) Close() error {
	s.cleanupWG.Wait()
	return s.db.Close()
}

func (s *SQLiteStore) Set(code string, m *models.URLMapping) error {
	var expiresAt sql.NullInt64
	if m.ExpiresAt != nil {
		expiresAt = sql.NullInt64{Int64: m.ExpiresAt.UnixNano(), Valid: true}
	}
	tagsJSON, err := encodeTags(m.Tags)
	if err != nil {
		return err
	}
	// INSERT OR IGNORE leaves any existing row untouched and signals the
	// conflict via RowsAffected==0. We surface that as ErrCodeConflict so
	// the shorten handler can return 409 even when the prior Exists check
	// passed (the TOCTOU race window between Exists and Set). This is the
	// non-upsert contract described on MemoryStore.Set.
	res, err := s.db.Exec(
		`INSERT OR IGNORE INTO urls (short_code, original_url, created_at, expires_at, click_count, last_accessed, owner_token_hash, tags, max_clicks, password_hash, password_salt)
		 VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?)`,
		code, m.OriginalURL, m.CreatedAt.UnixNano(), expiresAt, m.ClickCount, m.OwnerTokenHash,
		tagsJSON, nullableInt(m.MaxClicks), nullableBlob(m.PasswordHash), nullableBlob(m.PasswordSalt),
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrCodeConflict
	}
	return nil
}

// encodeTags marshals an owner-supplied tag slice into the TEXT column.
// An empty/nil slice maps to SQL NULL so the column stays compact and
// downstream scanners can treat NULL == "no tags" uniformly.
func encodeTags(tags []string) (any, error) {
	if len(tags) == 0 {
		return nil, nil
	}
	b, err := json.Marshal(tags)
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

// nullableInt maps a Go int64 of 0 to SQL NULL — used for max_clicks where
// 0 has the same semantic as "unset" (unlimited).
func nullableInt(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

// nullableBlob maps an empty slice to SQL NULL — used for the password
// hash/salt columns so absence is distinguishable from a zero-length value.
func nullableBlob(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func (s *SQLiteStore) Get(code string) (*models.URLMapping, error) {
	var (
		originalURL    string
		createdAt      int64
		expiresAt      sql.NullInt64
		clickCount     int64
		lastAccessed   sql.NullInt64
		ownerTokenHash []byte
		tagsJSON       sql.NullString
		maxClicks      sql.NullInt64
		passwordHash   []byte
		passwordSalt   []byte
	)
	err := s.db.QueryRow(
		`SELECT original_url, created_at, expires_at, click_count, last_accessed, owner_token_hash,
		        tags, max_clicks, password_hash, password_salt
		 FROM urls WHERE short_code = ?`, code,
	).Scan(&originalURL, &createdAt, &expiresAt, &clickCount, &lastAccessed, &ownerTokenHash,
		&tagsJSON, &maxClicks, &passwordHash, &passwordSalt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	m := &models.URLMapping{
		ID:             code,
		OriginalURL:    originalURL,
		CreatedAt:      time.Unix(0, createdAt),
		ClickCount:     clickCount,
		OwnerTokenHash: ownerTokenHash,
		PasswordHash:   passwordHash,
		PasswordSalt:   passwordSalt,
	}
	if expiresAt.Valid {
		t := time.Unix(0, expiresAt.Int64)
		m.ExpiresAt = &t
	}
	if lastAccessed.Valid {
		t := time.Unix(0, lastAccessed.Int64)
		m.LastAccessed = &t
	}
	if tagsJSON.Valid && tagsJSON.String != "" {
		if err := json.Unmarshal([]byte(tagsJSON.String), &m.Tags); err != nil {
			// Corrupt JSON in the tags column is treated as "no tags" rather
			// than a hard error — the redirect path shouldn't fail because
			// of a malformed metadata field.
			slog.Warn("sqlite: malformed tags JSON", "code", code, "err", err)
			m.Tags = nil
		}
	}
	if maxClicks.Valid {
		m.MaxClicks = maxClicks.Int64
	}
	if m.ExpiresAt != nil && time.Now().After(*m.ExpiresAt) {
		return nil, ErrExpired
	}
	return m, nil
}

// Delete removes a mapping. Returns ErrNotFound if no row was affected so
// the handler can distinguish a delete-of-missing-code from a real error.
func (s *SQLiteStore) Delete(code string) error {
	res, err := s.db.Exec(`DELETE FROM urls WHERE short_code = ?`, code)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// Ping verifies the database is reachable. Used by /readyz; we delegate to
// database/sql which already manages a connection pool with health checks.
func (s *SQLiteStore) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *SQLiteStore) Exists(code string) bool {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM urls WHERE short_code = ? LIMIT 1`, code).Scan(&one)
	return err == nil
}

// RecordClick atomically increments click_count + last_accessed and inserts
// the event row in a single transaction. Either both writes commit or
// neither does — analytics consumers can rely on click_count and the events
// table staying in sync (give or take an in-flight transaction). The
// previous design used two separate Exec calls and could drift by one if
// the second failed after the first succeeded.
//
// The Exists() pre-check the old separate methods relied on is gone:
// UPDATE...RowsAffected==0 is the canonical "not found" signal, and folding
// it into the transaction shaves an extra round-trip off the redirect path.
func (s *SQLiteStore) RecordClick(code string, ev models.ClickEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	// Rollback is a no-op after Commit; calling it unconditionally on the
	// way out covers every error-path return without bespoke cleanup code.
	defer func() { _ = tx.Rollback() }()

	res, err := tx.Exec(
		`UPDATE urls SET click_count = click_count + 1, last_accessed = ? WHERE short_code = ?`,
		ev.At.UnixNano(), code,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}

	if _, err := tx.Exec(
		`INSERT INTO click_events (short_code, clicked_at, ip_hash, referer, ua_class)
		 VALUES (?, ?, ?, ?, ?)`,
		code, ev.At.UnixNano(), nullableText(ev.IPHash), nullableText(ev.Referer), nullableText(ev.UAClass),
	); err != nil {
		return err
	}

	return tx.Commit()
}

// RecentClicks returns up to limit events for code, newest first.
func (s *SQLiteStore) RecentClicks(code string, limit int) ([]models.ClickEvent, error) {
	if !s.Exists(code) {
		return nil, ErrNotFound
	}
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(
		`SELECT clicked_at, ip_hash, referer, ua_class
		 FROM click_events WHERE short_code = ?
		 ORDER BY clicked_at DESC LIMIT ?`,
		code, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]models.ClickEvent, 0)
	for rows.Next() {
		var (
			ts                       int64
			ipHash, referer, uaClass sql.NullString
		)
		if err := rows.Scan(&ts, &ipHash, &referer, &uaClass); err != nil {
			return nil, err
		}
		out = append(out, models.ClickEvent{
			At:      time.Unix(0, ts),
			IPHash:  ipHash.String,
			Referer: referer.String,
			UAClass: uaClass.String,
		})
	}
	return out, rows.Err()
}

// RotateToken replaces the owner-token hash. UPDATE returns 0 rows when
// the code doesn't exist; surface that as ErrNotFound. Authorisation is
// the handler's responsibility — this method does not verify the OLD
// hash before writing the new one.
func (s *SQLiteStore) RotateToken(code string, newHash []byte) error {
	res, err := s.db.Exec(
		`UPDATE urls SET owner_token_hash = ? WHERE short_code = ?`,
		newHash, code,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// Update overwrites mutable fields. Each non-nil pointer / Clear flag in
// UpdateFields adds a `col = ?` fragment; columns not mentioned are left
// alone. The handler is expected to combine the PATCH body with current row
// state and submit only the deltas.
func (s *SQLiteStore) Update(code string, f UpdateFields) error {
	sets := make([]string, 0, 6)
	args := make([]any, 0, 7)

	if f.OriginalURL != nil {
		sets = append(sets, "original_url = ?")
		args = append(args, *f.OriginalURL)
	}
	switch {
	case f.ClearExpiration:
		sets = append(sets, "expires_at = ?")
		args = append(args, nil)
	case f.ExpiresAt != nil:
		sets = append(sets, "expires_at = ?")
		args = append(args, f.ExpiresAt.UnixNano())
	}
	if f.Tags != nil {
		enc, err := encodeTags(*f.Tags)
		if err != nil {
			return err
		}
		sets = append(sets, "tags = ?")
		args = append(args, enc)
	}
	if f.MaxClicks != nil {
		sets = append(sets, "max_clicks = ?")
		args = append(args, nullableInt(*f.MaxClicks))
	}
	switch {
	case f.ClearPassword:
		sets = append(sets, "password_hash = ?", "password_salt = ?")
		args = append(args, nil, nil)
	case f.PasswordHash != nil:
		sets = append(sets, "password_hash = ?", "password_salt = ?")
		args = append(args, nullableBlob(f.PasswordHash), nullableBlob(f.PasswordSalt))
	}

	if len(sets) == 0 {
		// Nothing to change — treat as success if the row exists.
		if !s.Exists(code) {
			return ErrNotFound
		}
		return nil
	}
	args = append(args, code)
	res, err := s.db.Exec(
		`UPDATE urls SET `+strings.Join(sets, ", ")+` WHERE short_code = ?`, args...,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ClicksByBucket aggregates click_events into fixed-width buckets so the
// analytics UI can draw a sparkline over a configurable window without
// pulling every raw event. The bucket boundaries are computed in SQL via
// integer division of clicked_at by the bucket width (both in nanoseconds);
// the result slice is positional (oldest at index 0), matching the
// MemoryStore implementation.
func (s *SQLiteStore) ClicksByBucket(code string, until time.Time, bucket time.Duration, count int) ([]int64, error) {
	if count <= 0 || bucket <= 0 {
		return nil, nil
	}
	if !s.Exists(code) {
		return nil, ErrNotFound
	}
	windowStart := until.Add(-time.Duration(count) * bucket)
	rows, err := s.db.Query(
		`SELECT (clicked_at - ?) / ? AS bucket_idx, COUNT(*)
		 FROM click_events
		 WHERE short_code = ? AND clicked_at >= ? AND clicked_at < ?
		 GROUP BY bucket_idx`,
		windowStart.UnixNano(), bucket.Nanoseconds(), code,
		windowStart.UnixNano(), until.UnixNano(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]int64, count)
	for rows.Next() {
		var idx, n int64
		if err := rows.Scan(&idx, &n); err != nil {
			return nil, err
		}
		if idx >= 0 && idx < int64(count) {
			out[idx] = n
		}
	}
	return out, rows.Err()
}

func (s *SQLiteStore) StartCleanupRoutine(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	s.cleanupWG.Add(1)
	go func() {
		defer s.cleanupWG.Done()
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				// Bail out if cancellation arrived between ticks — Go's
				// select picks randomly when both channels are ready, so
				// without this guard we could run one more Exec after
				// Close has already been signalled to wait on us.
				if ctx.Err() != nil {
					return
				}
				if _, err := s.db.ExecContext(ctx,
					`DELETE FROM urls WHERE expires_at IS NOT NULL AND expires_at < ?`,
					now.UnixNano(),
				); err != nil && !errors.Is(err, context.Canceled) {
					slog.Error("sqlite cleanup (urls)", "err", err)
				}
				if s.clickRetention > 0 {
					cutoff := now.Add(-s.clickRetention).UnixNano()
					if _, err := s.db.ExecContext(ctx,
						`DELETE FROM click_events WHERE clicked_at < ?`, cutoff,
					); err != nil && !errors.Is(err, context.Canceled) {
						slog.Error("sqlite cleanup (clicks)", "err", err)
					}
				}
			}
		}
	}()
}

// nullableText is a small helper that maps "" → NULL so empty fields don't
// blur with explicit empties when scanning back.
func nullableText(s string) any {
	if s == "" {
		return nil
	}
	return s
}

