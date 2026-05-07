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
}

// ShortenRequest represents the request to create a shortened URL
type ShortenRequest struct {
	URL            string `json:"url"`
	ExpirationMins int    `json:"expiration_mins,omitempty"` // Optional, 0 = no expiration
	CustomCode     string `json:"custom_code,omitempty"`     // Optional, fall back to random when empty
}

// ShortenResponse represents the response containing the shortened URL
type ShortenResponse struct {
	ShortCode   string     `json:"short_code"`
	ShortURL    string     `json:"short_url"`
	OriginalURL string     `json:"original_url"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	AdminToken  string     `json:"admin_token"` // returned once; required to read analytics for this code
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
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}
