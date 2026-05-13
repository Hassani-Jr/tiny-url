package services

import (
	"database/sql"
	"time"
	"tiny-url/models"
)

// LogAudit / RecentAuditEvents for SQLite. Mirrors the in-memory
// implementation's contract: best-effort write, newest-first reads,
// limit/offset pagination. Implemented in a shared file because the
// SQL is so close to the Postgres equivalent — only the placeholder
// dialect differs (covered in storage_postgres_audit.go).

// LogAudit inserts an audit event row. The caller may leave ev.At
// zero; we stamp it server-side so an attacker-controlled timestamp
// can't appear in the log.
func (s *SQLiteStore) LogAudit(ev models.AuditEvent) error {
	if ev.At.IsZero() {
		ev.At = time.Now()
	}
	_, err := s.db.Exec(
		`INSERT INTO audit_events (at, actor_kind, actor_id, action, target_kind, target_id, metadata, request_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.At.UnixNano(), ev.ActorKind, ev.ActorID, ev.Action, ev.TargetKind, ev.TargetID,
		nullableText(ev.Metadata), nullableText(ev.RequestID),
	)
	return err
}

// RecentAuditEvents returns events newest-first with limit/offset
// pagination. Same defaults as the analytics clicks endpoint.
func (s *SQLiteStore) RecentAuditEvents(limit, offset int) ([]models.AuditEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.Query(
		`SELECT id, at, actor_kind, actor_id, action, target_kind, target_id, metadata, request_id
		 FROM audit_events
		 ORDER BY at DESC, id DESC
		 LIMIT ? OFFSET ?`,
		limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAuditRows(rows)
}

// scanAuditRows is shared between the SQLite and Postgres readers — the
// row layout matches even though the placeholder syntax differs in the
// originating query. Keeping the decode in one place means a future
// column addition only needs one edit.
func scanAuditRows(rows *sql.Rows) ([]models.AuditEvent, error) {
	out := make([]models.AuditEvent, 0)
	for rows.Next() {
		var (
			id                         int64
			at                         int64
			actorKind, actorID, action string
			targetKind, targetID       string
			metadata, requestID        sql.NullString
		)
		if err := rows.Scan(&id, &at, &actorKind, &actorID, &action, &targetKind, &targetID, &metadata, &requestID); err != nil {
			return nil, err
		}
		out = append(out, models.AuditEvent{
			ID:         id,
			At:         time.Unix(0, at),
			ActorKind:  actorKind,
			ActorID:    actorID,
			Action:     action,
			TargetKind: targetKind,
			TargetID:   targetID,
			Metadata:   metadata.String,
			RequestID:  requestID.String,
		})
	}
	return out, rows.Err()
}
