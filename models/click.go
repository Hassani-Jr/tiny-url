package models

import "time"

// ClickEvent records a single redirect for a short code. Stored in the
// per-code event log surfaced via /api/analytics/{code}/clicks.
//
// Privacy posture: raw User-Agent is intentionally NOT stored (it's a strong
// browser/OS fingerprinting vector and a targeting hint for exploit kits).
// Raw IP is also not stored — only an optional salted SHA-256 (controlled
// by CLICK_LOG_IP) so a database leak cannot be used to recover IPs without
// also leaking the per-process salt.
type ClickEvent struct {
	At      time.Time `json:"at"`
	IPHash  string    `json:"ip_hash,omitempty"`  // hex SHA-256 of IP+salt; "" when CLICK_LOG_IP=false
	Referer string    `json:"referer,omitempty"`  // truncated to MaxRefererLength
	UAClass string    `json:"ua_class,omitempty"` // "bot" | "mobile" | "tablet" | "desktop" | "unknown"
}
