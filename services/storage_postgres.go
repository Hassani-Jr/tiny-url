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

	_ "github.com/jackc/pgx/v5/stdlib"
)

// PostgresStore is a durable Store backed by Postgres via the pgx
// driver (registered under the "pgx" name from pgx/v5/stdlib). Used
// when a single-binary SQLite deploy is no longer enough — multi-
// replica installs need a network database so two redirect handlers on
// different hosts see the same click_events table.
//
// The schema mirrors the SQLite backend column-for-column so the model
// layer is unchanged. Timestamps are stored as BIGINT nanoseconds-
// since-epoch for parity (a TIMESTAMP column would be nicer in
// isolation but cross-backend code would have to special-case the
// conversion). BYTEA holds token hashes and other small binary blobs;
// JSONB would be a better fit for tags but we use TEXT-encoded JSON to
// keep the SQL identical between backends.
type PostgresStore struct {
	db             *sql.DB
	clickRetention time.Duration
	// cleanupWG joins the cleanup goroutine on Close so a deferred
	// Cleanup() in tests doesn't race db.Close() — same rationale as
	// SQLiteStore.cleanupWG.
	cleanupWG sync.WaitGroup
}

// postgresSchema is the initial DDL. ADD COLUMN IF NOT EXISTS is
// available in Postgres 9.6+ so we don't need the duplicate-column
// catch the SQLite backend uses; the column list lives below as a
// straightforward series of ALTERs that run idempotently on every
// startup.
const postgresSchema = `
CREATE TABLE IF NOT EXISTS urls (
    short_code        TEXT PRIMARY KEY,
    original_url      TEXT NOT NULL,
    created_at        BIGINT NOT NULL,
    expires_at        BIGINT,
    click_count       BIGINT NOT NULL DEFAULT 0,
    last_accessed     BIGINT,
    owner_token_hash  BYTEA
);
CREATE INDEX IF NOT EXISTS idx_urls_expires_at ON urls(expires_at)
    WHERE expires_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS click_events (
    id          BIGSERIAL PRIMARY KEY,
    short_code  TEXT NOT NULL REFERENCES urls(short_code) ON DELETE CASCADE,
    clicked_at  BIGINT NOT NULL,
    ip_hash     TEXT,
    referer     TEXT,
    ua_class    TEXT
);
CREATE INDEX IF NOT EXISTS idx_click_events_code_time
    ON click_events(short_code, clicked_at DESC);

CREATE TABLE IF NOT EXISTS api_keys (
    id           BIGSERIAL PRIMARY KEY,
    token_hash   BYTEA NOT NULL UNIQUE,
    label        TEXT,
    created_at   BIGINT NOT NULL,
    last_used_at BIGINT
);

CREATE TABLE IF NOT EXISTS audit_events (
    id          BIGSERIAL PRIMARY KEY,
    at          BIGINT NOT NULL,
    actor_kind  TEXT NOT NULL,
    actor_id    TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    target_id   TEXT NOT NULL DEFAULT '',
    metadata    TEXT,
    request_id  TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_events(at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_events(actor_kind, actor_id);
`

// postgresMigrations adds columns introduced after the initial schema
// shipped. Each statement uses IF NOT EXISTS so re-running on an
// already-migrated database is a no-op. Order matches the SQLite
// migrations so the two backends are conceptually aligned.
var postgresMigrations = []string{
	`ALTER TABLE urls ADD COLUMN IF NOT EXISTS tags TEXT`,
	`ALTER TABLE urls ADD COLUMN IF NOT EXISTS max_clicks BIGINT`,
	`ALTER TABLE urls ADD COLUMN IF NOT EXISTS password_hash BYTEA`,
	`ALTER TABLE urls ADD COLUMN IF NOT EXISTS password_salt BYTEA`,
	`ALTER TABLE urls ADD COLUMN IF NOT EXISTS webhook_url TEXT`,
	`ALTER TABLE urls ADD COLUMN IF NOT EXISTS webhook_secret BYTEA`,
	`ALTER TABLE click_events ADD COLUMN IF NOT EXISTS country TEXT`,
	`ALTER TABLE urls ADD COLUMN IF NOT EXISTS api_key_id BIGINT`,
	`ALTER TABLE urls ADD COLUMN IF NOT EXISTS preview_title TEXT`,
	`ALTER TABLE urls ADD COLUMN IF NOT EXISTS preview_image TEXT`,
	`ALTER TABLE urls ADD COLUMN IF NOT EXISTS preview_description TEXT`,
	`ALTER TABLE urls ADD COLUMN IF NOT EXISTS preview_fetched_at BIGINT`,
}

// NewPostgresStore opens a connection pool against dsn and applies the
// schema. dsn is anything pgx accepts:
//
//	postgres://user:pass@host:5432/dbname?sslmode=require
//	host=db user=app password=... dbname=tinyurl sslmode=disable
//
// The pool size is left at database/sql's defaults (unbounded);
// operators who need to cap it can set SetMaxOpenConns externally —
// exposing that knob in Config is left for later if observed contention
// suggests it matters.
func NewPostgresStore(dsn string) (*PostgresStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres open: %w", err)
	}
	// Ping with a short timeout so a misconfigured DSN fails startup
	// fast instead of hanging on the default connection establishment.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("postgres ping: %w", err)
	}
	if _, err := db.Exec(postgresSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("postgres schema: %w", err)
	}
	for _, stmt := range postgresMigrations {
		if _, err := db.Exec(stmt); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("postgres migrate %q: %w", stmt, err)
		}
	}
	return &PostgresStore{db: db}, nil
}

// SetClickRetention mirrors SQLiteStore.SetClickRetention.
func (s *PostgresStore) SetClickRetention(d time.Duration) {
	s.clickRetention = d
}

// Close waits for the cleanup goroutine before closing the pool —
// same join-on-shutdown contract as SQLite.
func (s *PostgresStore) Close() error {
	s.cleanupWG.Wait()
	return s.db.Close()
}

func (s *PostgresStore) Set(code string, m *models.URLMapping) error {
	tagsJSON, err := encodeTags(m.Tags)
	if err != nil {
		return err
	}
	var expiresAt any
	if m.ExpiresAt != nil {
		expiresAt = m.ExpiresAt.UnixNano()
	}
	var previewFetched any
	if m.PreviewFetchedAt != nil {
		previewFetched = m.PreviewFetchedAt.UnixNano()
	}
	// ON CONFLICT DO NOTHING is Postgres's INSERT-IGNORE; we read
	// RowsAffected to detect the collision, matching the SQLite
	// "INSERT OR IGNORE → RowsAffected==0" contract.
	res, err := s.db.Exec(
		`INSERT INTO urls (short_code, original_url, created_at, expires_at, click_count, last_accessed, owner_token_hash, tags, max_clicks, password_hash, password_salt, webhook_url, webhook_secret, api_key_id, preview_title, preview_image, preview_description, preview_fetched_at)
		 VALUES ($1, $2, $3, $4, $5, NULL, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
		 ON CONFLICT (short_code) DO NOTHING`,
		code, m.OriginalURL, m.CreatedAt.UnixNano(), expiresAt, m.ClickCount, m.OwnerTokenHash,
		tagsJSON, nullableInt(m.MaxClicks), nullableBlob(m.PasswordHash), nullableBlob(m.PasswordSalt),
		nullableText(m.WebhookURL), nullableBlob(m.WebhookSecret), nullableInt(m.APIKeyID),
		nullableText(m.PreviewTitle), nullableText(m.PreviewImage), nullableText(m.PreviewDescription),
		previewFetched,
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

func (s *PostgresStore) Get(code string) (*models.URLMapping, error) {
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
		webhookURL     sql.NullString
		webhookSecret  []byte
		apiKeyID       sql.NullInt64
		previewTitle   sql.NullString
		previewImage   sql.NullString
		previewDesc    sql.NullString
		previewFetched sql.NullInt64
	)
	err := s.db.QueryRow(
		`SELECT original_url, created_at, expires_at, click_count, last_accessed, owner_token_hash,
		        tags, max_clicks, password_hash, password_salt, webhook_url, webhook_secret, api_key_id,
		        preview_title, preview_image, preview_description, preview_fetched_at
		 FROM urls WHERE short_code = $1`, code,
	).Scan(&originalURL, &createdAt, &expiresAt, &clickCount, &lastAccessed, &ownerTokenHash,
		&tagsJSON, &maxClicks, &passwordHash, &passwordSalt, &webhookURL, &webhookSecret, &apiKeyID,
		&previewTitle, &previewImage, &previewDesc, &previewFetched)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	m := &models.URLMapping{
		ID:                 code,
		OriginalURL:        originalURL,
		CreatedAt:          time.Unix(0, createdAt),
		ClickCount:         clickCount,
		OwnerTokenHash:     ownerTokenHash,
		PasswordHash:       passwordHash,
		PasswordSalt:       passwordSalt,
		WebhookURL:         webhookURL.String,
		WebhookSecret:      webhookSecret,
		APIKeyID:           apiKeyID.Int64,
		PreviewTitle:       previewTitle.String,
		PreviewImage:       previewImage.String,
		PreviewDescription: previewDesc.String,
	}
	if previewFetched.Valid {
		t := time.Unix(0, previewFetched.Int64)
		m.PreviewFetchedAt = &t
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
			slog.Warn("postgres: malformed tags JSON", "code", code, "err", err)
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

func (s *PostgresStore) Delete(code string) error {
	res, err := s.db.Exec(`DELETE FROM urls WHERE short_code = $1`, code)
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

func (s *PostgresStore) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *PostgresStore) Exists(code string) bool {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM urls WHERE short_code = $1 LIMIT 1`, code).Scan(&one)
	return err == nil
}

// RecordClick mirrors SQLite's atomic-in-a-transaction implementation
// so the counter and event log stay in sync. Postgres handles the
// UPDATE + INSERT in a single transaction trivially; READ COMMITTED is
// fine because the increment is via `click_count + 1` not a read-modify-
// write at the application level.
func (s *PostgresStore) RecordClick(code string, ev models.ClickEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.Exec(
		`UPDATE urls SET click_count = click_count + 1, last_accessed = $1 WHERE short_code = $2`,
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
		`INSERT INTO click_events (short_code, clicked_at, ip_hash, referer, ua_class, country)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		code, ev.At.UnixNano(), nullableText(ev.IPHash), nullableText(ev.Referer), nullableText(ev.UAClass), nullableText(ev.Country),
	); err != nil {
		return err
	}

	return tx.Commit()
}

func (s *PostgresStore) RecentClicks(code string, limit int) ([]models.ClickEvent, error) {
	if !s.Exists(code) {
		return nil, ErrNotFound
	}
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(
		`SELECT clicked_at, ip_hash, referer, ua_class, country
		 FROM click_events WHERE short_code = $1
		 ORDER BY clicked_at DESC LIMIT $2`,
		code, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]models.ClickEvent, 0)
	for rows.Next() {
		var (
			ts                                int64
			ipHash, referer, uaClass, country sql.NullString
		)
		if err := rows.Scan(&ts, &ipHash, &referer, &uaClass, &country); err != nil {
			return nil, err
		}
		out = append(out, models.ClickEvent{
			At:      time.Unix(0, ts),
			IPHash:  ipHash.String,
			Referer: referer.String,
			UAClass: uaClass.String,
			Country: country.String,
		})
	}
	return out, rows.Err()
}

func (s *PostgresStore) RotateToken(code string, newHash []byte) error {
	res, err := s.db.Exec(
		`UPDATE urls SET owner_token_hash = $1 WHERE short_code = $2`,
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

// Update reuses the same incremental-SET pattern as the SQLite Update.
// Postgres placeholders are positional ($1, $2, …) so we have to
// renumber them based on how many sets we've already accumulated —
// minor extra bookkeeping vs. SQLite's "?" but otherwise identical.
func (s *PostgresStore) Update(code string, f UpdateFields) error {
	sets := make([]string, 0, 8)
	args := make([]any, 0, 10)
	next := func() string {
		args = append(args, nil) // placeholder; replaced via index below
		return fmt.Sprintf("$%d", len(args))
	}

	if f.OriginalURL != nil {
		sets = append(sets, "original_url = "+next())
		args[len(args)-1] = *f.OriginalURL
	}
	switch {
	case f.ClearExpiration:
		sets = append(sets, "expires_at = "+next())
		args[len(args)-1] = nil
	case f.ExpiresAt != nil:
		sets = append(sets, "expires_at = "+next())
		args[len(args)-1] = f.ExpiresAt.UnixNano()
	}
	if f.Tags != nil {
		enc, err := encodeTags(*f.Tags)
		if err != nil {
			return err
		}
		sets = append(sets, "tags = "+next())
		args[len(args)-1] = enc
	}
	if f.MaxClicks != nil {
		sets = append(sets, "max_clicks = "+next())
		args[len(args)-1] = nullableInt(*f.MaxClicks)
	}
	switch {
	case f.ClearPassword:
		sets = append(sets, "password_hash = "+next(), "password_salt = "+next())
		args[len(args)-2] = nil
		args[len(args)-1] = nil
	case f.PasswordHash != nil:
		sets = append(sets, "password_hash = "+next(), "password_salt = "+next())
		args[len(args)-2] = nullableBlob(f.PasswordHash)
		args[len(args)-1] = nullableBlob(f.PasswordSalt)
	}
	switch {
	case f.ClearWebhook:
		sets = append(sets, "webhook_url = "+next(), "webhook_secret = "+next())
		args[len(args)-2] = nil
		args[len(args)-1] = nil
	case f.WebhookURL != nil:
		sets = append(sets, "webhook_url = "+next(), "webhook_secret = "+next())
		args[len(args)-2] = nullableText(*f.WebhookURL)
		args[len(args)-1] = nullableBlob(f.WebhookSecret)
	}
	if f.APIKeyID != nil {
		sets = append(sets, "api_key_id = "+next())
		args[len(args)-1] = nullableInt(*f.APIKeyID)
	}
	if f.PreviewTitle != nil {
		sets = append(sets, "preview_title = "+next())
		args[len(args)-1] = nullableText(*f.PreviewTitle)
	}
	if f.PreviewImage != nil {
		sets = append(sets, "preview_image = "+next())
		args[len(args)-1] = nullableText(*f.PreviewImage)
	}
	if f.PreviewDescription != nil {
		sets = append(sets, "preview_description = "+next())
		args[len(args)-1] = nullableText(*f.PreviewDescription)
	}
	if f.SetPreviewFetched {
		sets = append(sets, "preview_fetched_at = "+next())
		args[len(args)-1] = time.Now().UnixNano()
	}

	if len(sets) == 0 {
		if !s.Exists(code) {
			return ErrNotFound
		}
		return nil
	}
	args = append(args, code)
	codePlaceholder := fmt.Sprintf("$%d", len(args))
	res, err := s.db.Exec(
		`UPDATE urls SET `+strings.Join(sets, ", ")+` WHERE short_code = `+codePlaceholder, args...,
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

// ClicksByBucket mirrors the SQLite implementation. Postgres has no
// integer-division operator surprise vs SQLite — both treat `/` as
// integer division when both operands are integers.
func (s *PostgresStore) ClicksByBucket(code string, until time.Time, bucket time.Duration, count int) ([]int64, error) {
	if count <= 0 || bucket <= 0 {
		return nil, nil
	}
	if !s.Exists(code) {
		return nil, ErrNotFound
	}
	windowStart := until.Add(-time.Duration(count) * bucket)
	rows, err := s.db.Query(
		`SELECT (clicked_at - $1) / $2 AS bucket_idx, COUNT(*)
		 FROM click_events
		 WHERE short_code = $3 AND clicked_at >= $4 AND clicked_at < $5
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

func (s *PostgresStore) StartCleanupRoutine(ctx context.Context, interval time.Duration) {
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
				if ctx.Err() != nil {
					return
				}
				if _, err := s.db.ExecContext(ctx,
					`DELETE FROM urls WHERE expires_at IS NOT NULL AND expires_at < $1`,
					now.UnixNano(),
				); err != nil && !errors.Is(err, context.Canceled) {
					slog.Error("postgres cleanup (urls)", "err", err)
				}
				if s.clickRetention > 0 {
					cutoff := now.Add(-s.clickRetention).UnixNano()
					if _, err := s.db.ExecContext(ctx,
						`DELETE FROM click_events WHERE clicked_at < $1`, cutoff,
					); err != nil && !errors.Is(err, context.Canceled) {
						slog.Error("postgres cleanup (clicks)", "err", err)
					}
				}
			}
		}
	}()
}
