package models

import "time"

// AuditEvent records a single state-changing action against the
// server. Stored independently of the affected row so a DELETE of a
// URL doesn't take its audit history with it.
//
// The intentional shape: actor (who did it) + target (what they did it
// to) + action (what they did) + free-form metadata for diagnostic
// detail. Reading the table back gives an operator a complete change
// history with no joins required.
type AuditEvent struct {
	ID         int64     `json:"id"`
	At         time.Time `json:"at"`
	ActorKind  string    `json:"actor_kind"` // "apikey" | "admin_token" | "anon" | "system"
	ActorID    string    `json:"actor_id,omitempty"`
	Action     string    `json:"action"`      // url.create, url.delete, api_key.revoke, …
	TargetKind string    `json:"target_kind"` // "url" | "api_key"
	TargetID   string    `json:"target_id,omitempty"`
	Metadata   string    `json:"metadata,omitempty"` // JSON; opaque
	RequestID  string    `json:"request_id,omitempty"`
}

// Audit action constants. Centralising the strings means a typo in a
// caller fails to compile; downstream consumers (the future /api/audit
// reader, log-aggregation tooling) can match on the same names.
const (
	AuditActionAPIKeyCreate       = "api_key.create"
	AuditActionAPIKeyRevoke       = "api_key.revoke"
	AuditActionAPIKeyLabelUpdated = "api_key.label_updated"

	AuditActionURLCreate       = "url.create"
	AuditActionURLDelete       = "url.delete"
	AuditActionURLPatch        = "url.patch"
	AuditActionURLTokenRotated = "url.token_rotated"
	AuditActionWebhookRotated  = "webhook.rotated"
)

// Audit actor kinds. The string values match the column contents so
// callers don't need translation when querying the table by hand.
const (
	AuditActorAPIKey     = "apikey"
	AuditActorAdminToken = "admin_token"
	AuditActorAnon       = "anon"
	AuditActorSystem     = "system"
)
