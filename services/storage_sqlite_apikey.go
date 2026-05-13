package services

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"time"
	"tiny-url/models"
)

// CreateAPIKey inserts a new key. The token_hash column has a UNIQUE
// constraint so a duplicate hash (vanishingly unlikely with 32 random
// bytes, but guarded anyway) surfaces as ErrCodeConflict — same
// semantics as a URL short-code collision.
func (s *SQLiteStore) CreateAPIKey(label string, tokenHash []byte) (*models.APIKey, error) {
	now := time.Now()
	res, err := s.db.Exec(
		`INSERT INTO api_keys (token_hash, label, created_at, last_used_at) VALUES (?, ?, ?, NULL)`,
		tokenHash, nullableText(label), now.UnixNano(),
	)
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
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

// LookupAPIKey resolves a token hash to its row + updates last_used_at.
// The update is best-effort: a failure here returns the looked-up key
// anyway, since auth shouldn't break because a metadata write hiccupped.
func (s *SQLiteStore) LookupAPIKey(tokenHash []byte) (*models.APIKey, error) {
	var (
		id         int64
		label      sql.NullString
		createdAt  int64
		lastUsedAt sql.NullInt64
	)
	err := s.db.QueryRow(
		`SELECT id, label, created_at, last_used_at FROM api_keys WHERE token_hash = ?`,
		tokenHash,
	).Scan(&id, &label, &createdAt, &lastUsedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if _, uerr := s.db.Exec(`UPDATE api_keys SET last_used_at = ? WHERE id = ?`, now.UnixNano(), id); uerr != nil {
		slog.Warn("api_keys: last_used_at update failed", "id", id, "err", uerr)
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

func (s *SQLiteStore) GetAPIKey(id int64) (*models.APIKey, error) {
	var (
		label      sql.NullString
		createdAt  int64
		lastUsedAt sql.NullInt64
		tokenHash  []byte
	)
	err := s.db.QueryRow(
		`SELECT token_hash, label, created_at, last_used_at FROM api_keys WHERE id = ?`,
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

// DeleteAPIKey removes the key row AND clears api_key_id on every URL
// that referenced it. Runs in a transaction so a crash mid-delete
// doesn't leave URLs pointing at a phantom key. URLs survive — the
// per-URL admin token is still a valid credential.
func (s *SQLiteStore) DeleteAPIKey(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`UPDATE urls SET api_key_id = NULL WHERE api_key_id = ?`, id); err != nil {
		return err
	}
	res, err := tx.Exec(`DELETE FROM api_keys WHERE id = ?`, id)
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

func (s *SQLiteStore) UpdateAPIKeyLabel(id int64, label string) error {
	res, err := s.db.Exec(`UPDATE api_keys SET label = ? WHERE id = ?`, nullableText(label), id)
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

// ListURLsByAPIKey returns URLs owned by id, newest first, paginated.
// The query order matches the in-memory backend so behaviour is
// consistent across STORAGE_BACKEND choices.
func (s *SQLiteStore) ListURLsByAPIKey(id int64, limit, offset int) ([]*models.URLMapping, error) {
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.Query(
		`SELECT short_code, original_url, created_at, expires_at, click_count, last_accessed,
		        tags, max_clicks, password_hash, webhook_url
		 FROM urls WHERE api_key_id = ?
		 ORDER BY created_at DESC
		 LIMIT ? OFFSET ?`,
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
			PasswordHash: passwordHash, // presence indicates has_password; full bytes not used by listing
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
			// Corrupt JSON yields nil tags rather than failing the whole
			// listing — mirrors the resilience in Get().
			_ = json.Unmarshal([]byte(tagsJSON.String), &m.Tags)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
