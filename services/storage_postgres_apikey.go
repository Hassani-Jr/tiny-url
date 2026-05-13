package services

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"time"
	"tiny-url/models"
)

// CreateAPIKey inserts a new key. `RETURNING id` lets us recover the
// auto-assigned BIGSERIAL value in the same round-trip, which is the
// idiomatic Postgres replacement for SQLite's LastInsertId.
func (s *PostgresStore) CreateAPIKey(label string, tokenHash []byte) (*models.APIKey, error) {
	now := time.Now()
	var id int64
	err := s.db.QueryRow(
		`INSERT INTO api_keys (token_hash, label, created_at, last_used_at)
		 VALUES ($1, $2, $3, NULL)
		 RETURNING id`,
		tokenHash, nullableText(label), now.UnixNano(),
	).Scan(&id)
	if err != nil {
		return nil, err
	}
	return &models.APIKey{
		ID:        id,
		TokenHash: append([]byte(nil), tokenHash...),
		Label:     label,
		CreatedAt: now,
	}, nil
}

// LookupAPIKey resolves a hash → row, then best-effort bumps
// last_used_at. The token_hash UNIQUE index makes this O(1) at scale.
func (s *PostgresStore) LookupAPIKey(tokenHash []byte) (*models.APIKey, error) {
	var (
		id         int64
		label      sql.NullString
		createdAt  int64
		lastUsedAt sql.NullInt64
	)
	err := s.db.QueryRow(
		`SELECT id, label, created_at, last_used_at FROM api_keys WHERE token_hash = $1`,
		tokenHash,
	).Scan(&id, &label, &createdAt, &lastUsedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if _, uerr := s.db.Exec(`UPDATE api_keys SET last_used_at = $1 WHERE id = $2`, now.UnixNano(), id); uerr != nil {
		slog.Warn("postgres api_keys: last_used_at update failed", "id", id, "err", uerr)
	}
	k := &models.APIKey{
		ID:        id,
		TokenHash: append([]byte(nil), tokenHash...),
		Label:     label.String,
		CreatedAt: time.Unix(0, createdAt),
	}
	t := now
	k.LastUsedAt = &t
	return k, nil
}

func (s *PostgresStore) GetAPIKey(id int64) (*models.APIKey, error) {
	var (
		label      sql.NullString
		createdAt  int64
		lastUsedAt sql.NullInt64
		tokenHash  []byte
	)
	err := s.db.QueryRow(
		`SELECT token_hash, label, created_at, last_used_at FROM api_keys WHERE id = $1`,
		id,
	).Scan(&tokenHash, &label, &createdAt, &lastUsedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	k := &models.APIKey{
		ID:        id,
		TokenHash: tokenHash,
		Label:     label.String,
		CreatedAt: time.Unix(0, createdAt),
	}
	if lastUsedAt.Valid {
		t := time.Unix(0, lastUsedAt.Int64)
		k.LastUsedAt = &t
	}
	return k, nil
}

// DeleteAPIKey clears api_key_id on dependent URLs then drops the key
// row, both inside a single transaction so a partial-failure can't
// orphan urls pointing at a phantom key id.
func (s *PostgresStore) DeleteAPIKey(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`UPDATE urls SET api_key_id = NULL WHERE api_key_id = $1`, id); err != nil {
		return err
	}
	res, err := tx.Exec(`DELETE FROM api_keys WHERE id = $1`, id)
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
	return tx.Commit()
}

func (s *PostgresStore) UpdateAPIKeyLabel(id int64, label string) error {
	res, err := s.db.Exec(`UPDATE api_keys SET label = $1 WHERE id = $2`, nullableText(label), id)
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

func (s *PostgresStore) ListURLsByAPIKey(id int64, limit, offset int) ([]*models.URLMapping, error) {
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.Query(
		`SELECT short_code, original_url, created_at, expires_at, click_count, last_accessed,
		        tags, max_clicks, password_hash, webhook_url
		 FROM urls WHERE api_key_id = $1
		 ORDER BY created_at DESC
		 LIMIT $2 OFFSET $3`,
		id, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]*models.URLMapping, 0)
	for rows.Next() {
		var (
			code         string
			originalURL  string
			createdAt    int64
			expiresAt    sql.NullInt64
			clickCount   int64
			lastAccessed sql.NullInt64
			tagsJSON     sql.NullString
			maxClicks    sql.NullInt64
			passwordHash []byte
			webhookURL   sql.NullString
		)
		if err := rows.Scan(&code, &originalURL, &createdAt, &expiresAt, &clickCount, &lastAccessed,
			&tagsJSON, &maxClicks, &passwordHash, &webhookURL); err != nil {
			return nil, err
		}
		m := &models.URLMapping{
			ID:           code,
			OriginalURL:  originalURL,
			CreatedAt:    time.Unix(0, createdAt),
			ClickCount:   clickCount,
			PasswordHash: passwordHash,
			WebhookURL:   webhookURL.String,
			APIKeyID:     id,
		}
		if expiresAt.Valid {
			t := time.Unix(0, expiresAt.Int64)
			m.ExpiresAt = &t
		}
		if lastAccessed.Valid {
			t := time.Unix(0, lastAccessed.Int64)
			m.LastAccessed = &t
		}
		if maxClicks.Valid {
			m.MaxClicks = maxClicks.Int64
		}
		if tagsJSON.Valid && tagsJSON.String != "" {
			_ = json.Unmarshal([]byte(tagsJSON.String), &m.Tags)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
