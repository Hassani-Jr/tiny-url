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
	unfurler             *services.Unfurler // may be nil — feature opt-in
}

// SetUnfurler injects the async preview-fetch dispatcher. nil disables
// the feature (the default); main.go wires a real instance when
// UNFURL_ENABLED is set. Kept as a separate setter instead of a
// constructor arg so existing test call sites don't all need updating.
func (h *ShortenHandler) SetUnfurler(u *services.Unfurler) {
	h.unfurler = u
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

// itemError is the typed error returned by shortenOne so the HTTP
// layer can map it to the right status code. Carries a stable `code`
// string for machine readers and a human-readable message — useful
// for the bulk endpoint where individual items can fail without
// failing the whole request.
type itemError struct {
	Status  int    `json:"-"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *itemError) Error() string { return e.Message }

// ServeHTTP handles a single POST /api/shorten request. Thin wrapper
// over shortenOne — same validation, same audit, same error shapes,
// just one item.
func (h *ShortenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Only POST method is allowed")
		return
	}
	apiKeyID := h.detectAPIKey(r)

	r.Body = http.MaxBytesReader(w, r.Body, h.maxBodyBytes)
	var req models.ShortenRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	resp, ierr := h.shortenOne(req, apiKeyID, requestIDFromContext(r))
	if ierr != nil {
		writeError(w, ierr.Status, ierr.Message)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// detectAPIKey resolves the request's bearer token to an API key ID
// (if any). A bearer that doesn't match any key is NOT an error — it
// silently falls through to the unauthenticated flow so a stale key
// in a client's localStorage doesn't break URL creation.
func (h *ShortenHandler) detectAPIKey(r *http.Request) int64 {
	_, hash := extractBearer(r)
	if hash == nil {
		return 0
	}
	if key, err := h.storage.LookupAPIKey(hash); err == nil {
		return key.ID
	}
	return 0
}

// shortenOne runs the full single-URL pipeline: validation → generate
// codes/tokens/secrets → persist → audit. Returns either a populated
// response or a typed item error. The bulk endpoint calls this in a
// loop, letting one bad item fail without failing the whole request.
func (h *ShortenHandler) shortenOne(req models.ShortenRequest, apiKeyID int64, reqID string) (*models.ShortenResponse, *itemError) {
	// Validate cheap things first (regex, in-memory lookup) before
	// doing DNS resolution for SSRF — saves work on bad requests and
	// lets the custom-alias collision error surface even when the URL
	// is invalid.
	var shortCode string
	if req.CustomCode != "" {
		if err := services.ValidateCustomCode(req.CustomCode); err != nil {
			return nil, &itemError{Status: http.StatusBadRequest, Code: "invalid_custom_code", Message: customCodeMessage(err)}
		}
		if h.storage.Exists(req.CustomCode) {
			return nil, &itemError{Status: http.StatusConflict, Code: "code_conflict", Message: "custom code is already in use"}
		}
		shortCode = req.CustomCode
	}

	if err := services.ValidateDestinationURL(req.URL, h.denyList); err != nil {
		return nil, &itemError{Status: http.StatusBadRequest, Code: "invalid_url", Message: validationMessage(err)}
	}

	if req.ExpirationMins < 0 {
		return nil, &itemError{Status: http.StatusBadRequest, Code: "invalid_expiration", Message: "expiration_mins must be non-negative"}
	}
	if req.ExpirationMins > h.maxExpirationMinutes {
		req.ExpirationMins = h.maxExpirationMinutes
	}

	tags, err := services.NormalizeTags(req.Tags)
	if err != nil {
		return nil, &itemError{Status: http.StatusBadRequest, Code: "invalid_tags", Message: tagsMessage(err)}
	}

	if req.MaxClicks < 0 {
		return nil, &itemError{Status: http.StatusBadRequest, Code: "invalid_max_clicks", Message: "max_clicks must be non-negative"}
	}

	var (
		pwHash []byte
		pwSalt []byte
	)
	if req.Password != "" {
		if len(req.Password) > 256 {
			return nil, &itemError{Status: http.StatusBadRequest, Code: "password_too_long", Message: "password too long"}
		}
		pwHash, pwSalt, err = hashPassword(req.Password)
		if err != nil {
			return nil, &itemError{Status: http.StatusInternalServerError, Code: "internal", Message: "Failed to hash password"}
		}
	}

	var webhookSecret []byte
	if req.WebhookURL != "" {
		if err := services.ValidateDestinationURL(req.WebhookURL, h.denyList); err != nil {
			return nil, &itemError{Status: http.StatusBadRequest, Code: "invalid_webhook_url", Message: "webhook_url: " + validationMessage(err)}
		}
		webhookSecret, err = generateWebhookSecret()
		if err != nil {
			return nil, &itemError{Status: http.StatusInternalServerError, Code: "internal", Message: "Failed to generate webhook secret"}
		}
	}

	if shortCode == "" {
		c, err := services.GenerateShortCode(h.storage)
		if err != nil {
			return nil, &itemError{Status: http.StatusInternalServerError, Code: "internal", Message: "Failed to generate short code"}
		}
		shortCode = c
	}

	token, hash, err := generateOwnerToken()
	if err != nil {
		return nil, &itemError{Status: http.StatusInternalServerError, Code: "internal", Message: "Failed to generate owner token"}
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
		if errors.Is(err, services.ErrCodeConflict) {
			return nil, &itemError{Status: http.StatusConflict, Code: "code_conflict", Message: "custom code is already in use"}
		}
		return nil, &itemError{Status: http.StatusInternalServerError, Code: "internal", Message: "Failed to store URL"}
	}

	resp := &models.ShortenResponse{
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
		resp.WebhookSecret = encodeWebhookSecret(webhookSecret)
	}

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
		RequestID:  reqID,
	})

	// Fire-and-forget unfurl. The dashboard polls analytics on the
	// next refresh and picks up the preview fields when they land —
	// no need for a synchronous fetch on the create path. nil
	// unfurler (the default) skips this entirely.
	if h.unfurler != nil {
		h.unfurler.Enqueue(services.UnfurlJob{Code: shortCode, URL: req.URL})
	}

	return resp, nil
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
