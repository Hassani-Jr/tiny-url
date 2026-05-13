package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
	"tiny-url/models"
	"tiny-url/services"
)

// ShortenHandler handles URL shortening requests
type ShortenHandler struct {
	storage              services.Store
	baseURL              string
	maxExpirationMinutes int
	maxBodyBytes         int64
	denyList             *services.DenyList // may be nil
}

// NewShortenHandler creates a new ShortenHandler. denyList may be nil when
// no abuse list is configured — handlers and validators are deny=nil safe.
func NewShortenHandler(storage services.Store, baseURL string, maxExpirationMinutes int, maxBodyBytes int64, denyList *services.DenyList) *ShortenHandler {
	return &ShortenHandler{
		storage:              storage,
		baseURL:              baseURL,
		maxExpirationMinutes: maxExpirationMinutes,
		maxBodyBytes:         maxBodyBytes,
		denyList:             denyList,
	}
}

// ServeHTTP handles the HTTP request for shortening a URL
func (h *ShortenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Only POST method is allowed")
		return
	}

	// If the caller authenticates with an API key, the resulting URL is
	// bound to that key (api_key_id). Unauthenticated callers continue
	// to use the per-URL admin token model — both paths return an
	// admin_token, so existing clients don't break.
	var apiKeyID int64
	if _, hash := extractBearer(r); hash != nil {
		if key, err := h.storage.LookupAPIKey(hash); err == nil {
			apiKeyID = key.ID
		}
		// A bearer that doesn't match any API key is NOT an error — we
		// fall through to the unauthenticated flow. This matters for the
		// dashboard, which may have a stale key in localStorage; the
		// shorten still works, the URL just isn't auto-claimed.
	}

	r.Body = http.MaxBytesReader(w, r.Body, h.maxBodyBytes)

	var req models.ShortenRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate cheap things first (regex, in-memory lookup) before doing DNS
	// resolution for SSRF — both saves work on bad requests and lets the
	// custom-alias collision error surface even when the URL is invalid.
	var shortCode string
	if req.CustomCode != "" {
		if err := services.ValidateCustomCode(req.CustomCode); err != nil {
			writeError(w, http.StatusBadRequest, customCodeMessage(err))
			return
		}
		if h.storage.Exists(req.CustomCode) {
			writeError(w, http.StatusConflict, "custom code is already in use")
			return
		}
		shortCode = req.CustomCode
	}

	if err := services.ValidateDestinationURL(req.URL, h.denyList); err != nil {
		writeError(w, http.StatusBadRequest, validationMessage(err))
		return
	}

	if req.ExpirationMins < 0 {
		writeError(w, http.StatusBadRequest, "expiration_mins must be non-negative")
		return
	}
	if req.ExpirationMins > h.maxExpirationMinutes {
		req.ExpirationMins = h.maxExpirationMinutes
	}

	tags, err := services.NormalizeTags(req.Tags)
	if err != nil {
		writeError(w, http.StatusBadRequest, tagsMessage(err))
		return
	}

	if req.MaxClicks < 0 {
		writeError(w, http.StatusBadRequest, "max_clicks must be non-negative")
		return
	}

	var (
		pwHash []byte
		pwSalt []byte
	)
	if req.Password != "" {
		// Cap the password length so an attacker can't make us spend CPU on
		// a multi-megabyte password before the body-size limit catches up.
		// 256 bytes is well past any human-typeable passphrase.
		if len(req.Password) > 256 {
			writeError(w, http.StatusBadRequest, "password too long")
			return
		}
		pwHash, pwSalt, err = hashPassword(req.Password)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to hash password")
			return
		}
	}

	var webhookSecret []byte
	if req.WebhookURL != "" {
		// Same SSRF + deny rules as the destination URL. A webhook target
		// pointing at 127.0.0.1 would let an attacker pivot through our
		// click-driven HTTP client to internal services.
		if err := services.ValidateDestinationURL(req.WebhookURL, h.denyList); err != nil {
			writeError(w, http.StatusBadRequest, "webhook_url: "+validationMessage(err))
			return
		}
		webhookSecret, err = generateWebhookSecret()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to generate webhook secret")
			return
		}
	}

	if shortCode == "" {
		c, err := services.GenerateShortCode(h.storage)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to generate short code")
			return
		}
		shortCode = c
	}

	token, hash, err := generateOwnerToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to generate owner token")
		return
	}

	var expiresAt *time.Time
	if req.ExpirationMins > 0 {
		t := time.Now().Add(time.Duration(req.ExpirationMins) * time.Minute)
		expiresAt = &t
	}

	urlMapping := &models.URLMapping{
		ID:             shortCode,
		OriginalURL:    req.URL,
		CreatedAt:      time.Now(),
		ExpiresAt:      expiresAt,
		ClickCount:     0,
		OwnerTokenHash: hash,
		Tags:           tags,
		MaxClicks:      req.MaxClicks,
		PasswordHash:   pwHash,
		PasswordSalt:   pwSalt,
		WebhookURL:     req.WebhookURL,
		WebhookSecret:  webhookSecret,
		APIKeyID:       apiKeyID,
	}
	if err := h.storage.Set(shortCode, urlMapping); err != nil {
		// Defense-in-depth for the Exists/Set TOCTOU race: another writer
		// may have claimed the same code between our Exists check and this
		// Set. The store now reports ErrCodeConflict instead of silently
		// overwriting, and we surface it as 409 Conflict.
		if errors.Is(err, services.ErrCodeConflict) {
			writeError(w, http.StatusConflict, "custom code is already in use")
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to store URL")
		return
	}

	response := models.ShortenResponse{
		ShortCode:   shortCode,
		ShortURL:    h.baseURL + "/" + shortCode,
		OriginalURL: req.URL,
		ExpiresAt:   expiresAt,
		AdminToken:  token,
		Tags:        tags,
		MaxClicks:   req.MaxClicks,
		HasPassword: len(pwHash) > 0,
		WebhookURL:  req.WebhookURL,
	}
	if len(webhookSecret) > 0 {
		// Returned ONCE — same contract as admin_token. Owner is
		// expected to save it; rotation re-issues with a new value.
		response.WebhookSecret = encodeWebhookSecret(webhookSecret)
	}

	// Audit: which credential created this URL? Anon when no bearer
	// was present; the API key otherwise. There's no admin-token case
	// at create time since the admin token doesn't exist until we
	// generate it above.
	actorKind, actorID := models.AuditActorAnon, ""
	if apiKeyID > 0 {
		actorKind, actorID = models.AuditActorAPIKey, fmt.Sprintf("%d", apiKeyID)
	}
	logAuditBestEffort(h.storage, models.AuditEvent{
		ActorKind:  actorKind,
		ActorID:    actorID,
		Action:     models.AuditActionURLCreate,
		TargetKind: "url",
		TargetID:   shortCode,
		RequestID:  requestIDFromContext(r),
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(response)
}

// generateOwnerToken returns a high-entropy bearer token (raw, returned once
// to the caller) and its SHA-256 hash (stored alongside the URL mapping).
// Storing only the hash means a database leak does not give an attacker the
// usable tokens.
func generateOwnerToken() (string, []byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(token))
	return token, h[:], nil
}

// generateWebhookSecret returns 32 cryptographically random bytes for use
// as an HMAC-SHA256 key. Unlike the admin token (where we store only the
// hash), the raw secret IS persisted — webhook signature verification on
// the receiver side requires the original key, so we can't one-way it.
// Stored as a BLOB column with the same row-level access controls as the
// destination URL.
func generateWebhookSecret() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// encodeWebhookSecret serialises the raw secret into the form returned to
// the API client. base64url with no padding matches the admin_token
// encoding and is URL-safe so receivers can embed it in env files
// without escaping.
func encodeWebhookSecret(secret []byte) string {
	return base64.RawURLEncoding.EncodeToString(secret)
}

func customCodeMessage(err error) string {
	switch {
	case errors.Is(err, services.ErrInvalidCustomCode):
		return "Custom code must be 3-32 characters of letters, digits, '_' or '-'"
	case errors.Is(err, services.ErrReservedCode):
		return "Custom code is reserved and cannot be used"
	default:
		return "Invalid custom code"
	}
}

func tagsMessage(err error) string {
	switch {
	case errors.Is(err, services.ErrInvalidTag):
		return "tag must be 1-32 characters after trimming"
	case errors.Is(err, services.ErrTooManyTags):
		return "too many tags (max 16)"
	default:
		return "invalid tags"
	}
}

func validationMessage(err error) string {
	switch {
	case errors.Is(err, services.ErrURLTooLong):
		return "URL exceeds maximum length"
	case errors.Is(err, services.ErrInvalidScheme):
		return "URL must start with http:// or https://"
	case errors.Is(err, services.ErrUserInfo):
		return "URL must not contain user credentials"
	case errors.Is(err, services.ErrDeniedHost):
		return "URL host is not permitted"
	case errors.Is(err, services.ErrPrivateAddress):
		return "URL host points at a private or reserved network"
	case errors.Is(err, services.ErrInvalidHost):
		return "URL host could not be resolved"
	default:
		return "Invalid URL"
	}
}

// writeError writes a JSON error response
func writeError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(models.ErrorResponse{
		Error:   http.StatusText(code),
		Message: message,
	})
}
