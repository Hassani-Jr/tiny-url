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
	// Country is an ISO-3166-1 alpha-2 code resolved from the client IP
	// at click time via the embedded GeoLite2 database. Empty when geoip
	// is disabled, the IP isn't in the DB, or the IP couldn't be parsed.
	// Country is coarse enough to keep the privacy posture (no city, no
	// lat/lon, no ASN).
	Country string `json:"country,omitempty"`
	// DestinationURL is which destination was served on this click.
	// Populated only for URLs with a Destinations pool — single-
	// destination URLs leave this empty (the OriginalURL is the only
	// possibility, no need to denormalize).
	DestinationURL string `json:"destination_url,omitempty"`
}
