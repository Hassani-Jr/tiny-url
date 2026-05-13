package services

import (
	"time"
	"tiny-url/models"
)

// Postgres audit log. The shape is identical to the SQLite version
// (see storage_audit.go) — only the placeholder dialect differs.

func (s *PostgresStore) LogAudit(ev models.AuditEvent) error {
	if ev.At.IsZero() {
		ev.At = time.Now()
	}
	_, err := s.db.Exec(
		`INSERT INTO audit_events (at, actor_kind, actor_id, action, target_kind, target_id, metadata, request_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		ev.At.UnixNano(), ev.ActorKind, ev.ActorID, ev.Action, ev.TargetKind, ev.TargetID,
		nullableText(ev.Metadata), nullableText(ev.RequestID),
	)
	return err
}

func (s *PostgresStore) RecentAuditEvents(limit, offset int) ([]models.AuditEvent, error) {
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
		 LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAuditRows(rows)
}
