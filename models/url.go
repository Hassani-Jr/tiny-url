package models

import "time"

// URLMapping represents a shortened URL with its metadata
type URLMapping struct {
	ID             string     // Short code (unique identifier)
	OriginalURL    string     // Full original URL
	CreatedAt      time.Time  // When the URL was created
	ExpiresAt      *time.Time // Optional expiration time (nil = never expires)
	ClickCount     int64      // Updated under the store mutex via atomic.AddInt64; read outside the lock via atomic.LoadInt64 (analytics handler holds no lock).
	LastAccessed   *time.Time // Last click timestamp
	OwnerTokenHash []byte     // SHA-256 of the admin token returned at create time; gates analytics access
	// Tags is an owner-supplied list of arbitrary string labels. Used by the
	// dashboard for grouping/filtering. The server treats them as opaque —
	// validation only enforces shape (count + per-tag length).
	Tags []string
	// MaxClicks bounds how many redirects this short URL can serve. 0 means
	// unlimited (the default). Once ClickCount >= MaxClicks the redirect
	// handler returns 410 Gone the same way it does for expired URLs — the
	// cleanup goroutine then reaps the row on its next pass.
	MaxClicks int64
	// PasswordHash, when non-empty, gates the redirect behind an interstitial
	// passphrase form. PBKDF2-SHA256 of (password || salt). Empty means the
	// short URL redirects without prompting.
	PasswordHash []byte
	// PasswordSalt is a per-URL 16-byte random salt for PasswordHash. Empty
	// iff PasswordHash is empty.
	PasswordSalt []byte
	// WebhookURL, when non-empty, is the HTTP endpoint the server POSTs to
	// after each successful click. Same SSRF rules as OriginalURL apply
	// (no private/loopback hosts). Server-generated WebhookSecret is the
	// HMAC-SHA256 key for the X-Tinyurl-Signature header on every delivery.
	WebhookURL    string
	WebhookSecret []byte
	// APIKeyID, when non-zero, is the ID of the API key that owns this
	// URL. The URL can be managed via either its per-URL admin token OR
	// the API key — both credentials work at all owner-gated endpoints.
	// Zero means "not associated with any API key"; the per-URL admin
	// token is the only credential.
	APIKeyID int64
	// Preview holds the unfurl metadata fetched asynchronously after
	// creation. Empty fields mean either "unfurl is disabled" or "the
	// fetch failed / returned nothing useful" — the dashboard treats
	// the empty case the same way and just hides the preview card.
	// PreviewFetchedAt is the only required signal of "we attempted
	// a fetch"; it stays nil for URLs created before unfurl shipped.
	PreviewTitle       string
	PreviewImage       string
	PreviewDescription string
	PreviewFetchedAt   *time.Time
	// Destinations is the weighted A/B routing pool. When non-empty,
	// the redirect handler picks one entry weighted-randomly instead
	// of using OriginalURL. OriginalURL stays populated for analytics
	// display + the QR target (the primary destination).
	Destinations []Destination
}

// Destination is one entry in a URL's weighted routing pool. Weight
// is a positive integer in [1, 100]; the redirect handler picks
// proportionally to weight / total. URLs are validated against the
// same SSRF + deny-list rules as the primary OriginalURL.
type Destination struct {
	URL    string `json:"url"`
	Weight int    `json:"weight"`
}

// ShortenRequest represents the request to create a shortened URL
type ShortenRequest struct {
	URL            string   `json:"url"`
	ExpirationMins int      `json:"expiration_mins,omitempty"` // Optional, 0 = no expiration
	CustomCode     string   `json:"custom_code,omitempty"`     // Optional, fall back to random when empty
	Tags           []string `json:"tags,omitempty"`            // Optional labels; opaque to server
	MaxClicks      int64    `json:"max_clicks,omitempty"`      // Optional cap; 0 = unlimited
	Password       string   `json:"password,omitempty"`        // Optional passphrase; gates redirect
	WebhookURL     string   `json:"webhook_url,omitempty"`     // Optional click webhook target
	// Destinations sets up A/B / weighted routing. Each entry is
	// validated like the primary URL (SSRF, deny-list, scheme).
	// When set, the redirect handler picks one weighted-randomly per
	// click instead of going straight to `url`. Up to 10 entries.
	Destinations []Destination `json:"destinations,omitempty"`
}

// ShortenResponse represents the response containing the shortened URL
type ShortenResponse struct {
	ShortCode     string        `json:"short_code"`
	ShortURL      string        `json:"short_url"`
	OriginalURL   string        `json:"original_url"`
	ExpiresAt     *time.Time    `json:"expires_at,omitempty"`
	AdminToken    string        `json:"admin_token"` // returned once; required to read analytics for this code
	Tags          []string      `json:"tags,omitempty"`
	MaxClicks     int64         `json:"max_clicks,omitempty"`
	HasPassword   bool          `json:"has_password,omitempty"`
	WebhookURL    string        `json:"webhook_url,omitempty"`
	WebhookSecret string        `json:"webhook_secret,omitempty"` // returned once when a webhook is configured; HMAC-SHA256 key
	Destinations  []Destination `json:"destinations,omitempty"`
}

// AnalyticsResponse represents analytics data for a shortened URL.
// Expired URLs return 410 Gone before this response is constructed, so the
// payload describes a live mapping only.
type AnalyticsResponse struct {
	ShortCode    string     `json:"short_code"`
	OriginalURL  string     `json:"original_url"`
	ClickCount   int64      `json:"click_count"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	LastAccessed *time.Time `json:"last_accessed,omitempty"`
	Tags         []string   `json:"tags,omitempty"`
	MaxClicks    int64      `json:"max_clicks,omitempty"`
	HasPassword  bool       `json:"has_password"`
	// WebhookURL is exposed (without the secret) so owners can see what's
	// configured. The secret was shown ONCE at create/rotate time and is
	// never returned again; lost secrets require a webhook rotation.
	WebhookURL string `json:"webhook_url,omitempty"`
	// Preview metadata fetched asynchronously after creation. Empty
	// fields are normal — most URLs have at most a title and image,
	// and the fields stay empty when unfurl is disabled or the fetch
	// failed. Clients should treat `preview_fetched_at == null` as
	// "not yet attempted".
	PreviewTitle       string     `json:"preview_title,omitempty"`
	PreviewImage       string     `json:"preview_image,omitempty"`
	PreviewDescription string     `json:"preview_description,omitempty"`
	PreviewFetchedAt   *time.Time `json:"preview_fetched_at,omitempty"`
	// Destinations exposes the routing pool to owners so the dashboard
	// can render the A/B configuration. Empty for single-destination
	// URLs (the common case) — clients should fall back to original_url.
	Destinations []Destination `json:"destinations,omitempty"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}
