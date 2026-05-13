package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"

	"tiny-url/models"
	"tiny-url/services"
)

// APIKeyHandler serves the /api/keys endpoint family. POST creates a new
// key; GET returns the calling key's metadata; PATCH updates label;
// DELETE revokes the calling key (URLs that referenced it survive — the
// per-URL admin token remains a valid credential).
//
// The contract is intentionally minimal: each API key is an independent
// identity. There is no user/account layer above keys. Operators who
// want multi-key "households" issue multiple keys; the label
// differentiates them.
type APIKeyHandler struct {
	storage services.Store
	// maxLabelLen mirrors the dashboard's local-label cap so the server
	// rejects pathological inputs (multi-megabyte label) before they hit
	// the storage layer.
	maxLabelLen int
}

func NewAPIKeyHandler(storage services.Store) *APIKeyHandler {
	return &APIKeyHandler{storage: storage, maxLabelLen: 64}
}

func (h *APIKeyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.create(w, r)
	case http.MethodGet:
		h.get(w, r)
	case http.MethodPatch:
		h.update(w, r)
	case http.MethodDelete:
		h.delete(w, r)
	default:
		w.Header().Set("Allow", "POST, GET, PATCH, DELETE")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// create issues a fresh API key. Auth: none — the endpoint is gated by
// the write rate limiter and the XHR-header CSRF check, same as
// POST /api/shorten. Anyone can mint a key for themselves; the value of
// the key comes from owning URLs you create with it, not from creating
// the key itself.
func (h *APIKeyHandler) create(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var req models.CreateAPIKeyRequest
	if r.ContentLength > 0 {
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid request body")
			return
		}
	}
	if len(req.Label) > h.maxLabelLen {
		writeError(w, http.StatusBadRequest, "label too long")
		return
	}
	rawToken, hash, err := generateAPIKeyToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}
	key, err := h.storage.CreateAPIKey(req.Label, hash)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to persist key")
		return
	}
	// Audit: anonymous actor (POST /api/keys takes no auth) creating
	// a new key. Target is the key itself, identified by its ID.
	logAuditBestEffort(h.storage, models.AuditEvent{
		ActorKind:  models.AuditActorAnon,
		Action:     models.AuditActionAPIKeyCreate,
		TargetKind: "api_key",
		TargetID:   fmt.Sprintf("%d", key.ID),
		RequestID:  requestIDFromContext(r),
	})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(models.CreateAPIKeyResponse{
		ID:        key.ID,
		Label:     key.Label,
		CreatedAt: key.CreatedAt,
		Token:     rawToken,
	})
}

// requireAPIKey resolves the bearer header to an API key or writes a
// 401 and returns nil. Centralises the "must be authenticated as an
// API key (not a per-URL admin token)" check used by the get/update/
// delete paths and by GET /api/urls.
func (h *APIKeyHandler) requireAPIKey(w http.ResponseWriter, r *http.Request) *models.APIKey {
	_, hash := extractBearer(r)
	if hash == nil {
		writeError(w, http.StatusUnauthorized, "missing API key")
		return nil
	}
	key, err := h.storage.LookupAPIKey(hash)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid API key")
		return nil
	}
	return key
}

func (h *APIKeyHandler) get(w http.ResponseWriter, r *http.Request) {
	key := h.requireAPIKey(w, r)
	if key == nil {
		return
	}
	writeAPIKeyJSON(w, http.StatusOK, key)
}

func (h *APIKeyHandler) update(w http.ResponseWriter, r *http.Request) {
	key := h.requireAPIKey(w, r)
	if key == nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var req struct {
		Label *string `json:"label"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Label == nil {
		writeError(w, http.StatusBadRequest, "label is required")
		return
	}
	if len(*req.Label) > h.maxLabelLen {
		writeError(w, http.StatusBadRequest, "label too long")
		return
	}
	if err := h.storage.UpdateAPIKeyLabel(key.ID, *req.Label); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update")
		return
	}
	logAuditBestEffort(h.storage, models.AuditEvent{
		ActorKind:  models.AuditActorAPIKey,
		ActorID:    fmt.Sprintf("%d", key.ID),
		Action:     models.AuditActionAPIKeyLabelUpdated,
		TargetKind: "api_key",
		TargetID:   fmt.Sprintf("%d", key.ID),
		RequestID:  requestIDFromContext(r),
	})
	key.Label = *req.Label
	writeAPIKeyJSON(w, http.StatusOK, key)
}

func (h *APIKeyHandler) delete(w http.ResponseWriter, r *http.Request) {
	key := h.requireAPIKey(w, r)
	if key == nil {
		return
	}
	if err := h.storage.DeleteAPIKey(key.ID); err != nil {
		if errors.Is(err, services.ErrNotFound) {
			// Lost a race with another revoker — already gone.
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to revoke")
		return
	}
	logAuditBestEffort(h.storage, models.AuditEvent{
		ActorKind:  models.AuditActorAPIKey,
		ActorID:    fmt.Sprintf("%d", key.ID),
		Action:     models.AuditActionAPIKeyRevoke,
		TargetKind: "api_key",
		TargetID:   fmt.Sprintf("%d", key.ID),
		RequestID:  requestIDFromContext(r),
	})
	w.WriteHeader(http.StatusNoContent)
}

func writeAPIKeyJSON(w http.ResponseWriter, status int, key *models.APIKey) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(models.APIKeyResponse{
		ID:         key.ID,
		Label:      key.Label,
		CreatedAt:  key.CreatedAt,
		LastUsedAt: key.LastUsedAt,
	})
}

// generateAPIKeyToken mints a fresh raw token + its SHA-256 hash, using
// the same scheme as the per-URL admin token. 32 random bytes,
// base64url no-pad encoded. The hash is what the store persists; the
// raw value is shown ONCE to the caller.
func generateAPIKeyToken() (string, []byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	tok := base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(tok))
	return tok, h[:], nil
}

// MyURLsHandler returns the paginated list of URLs owned by the calling
// API key. The response shape matches AnalyticsResponse so dashboards
// can render the listing without a follow-up per-row analytics fetch.
type MyURLsHandler struct {
	storage  services.Store
	maxLimit int
}

func NewMyURLsHandler(storage services.Store, maxLimit int) *MyURLsHandler {
	if maxLimit <= 0 {
		maxLimit = 100
	}
	return &MyURLsHandler{storage: storage, maxLimit: maxLimit}
}

type myURLsResponse struct {
	URLs []models.AnalyticsResponse `json:"urls"`
}

func (h *MyURLsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_, hash := extractBearer(r)
	if hash == nil {
		writeError(w, http.StatusUnauthorized, "missing API key")
		return
	}
	key, err := h.storage.LookupAPIKey(hash)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid API key")
		return
	}

	limit := parsePosInt(r.URL.Query().Get("limit"), 50, h.maxLimit)
	offset := parsePosInt(r.URL.Query().Get("offset"), 0, 1<<30)

	urls, err := h.storage.ListURLsByAPIKey(key.ID, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list URLs")
		return
	}

	out := make([]models.AnalyticsResponse, 0, len(urls))
	for _, u := range urls {
		out = append(out, models.AnalyticsResponse{
			ShortCode:    u.ID,
			OriginalURL:  u.OriginalURL,
			ClickCount:   atomic.LoadInt64(&u.ClickCount),
			CreatedAt:    u.CreatedAt,
			ExpiresAt:    u.ExpiresAt,
			LastAccessed: u.LastAccessed,
			Tags:         u.Tags,
			MaxClicks:    u.MaxClicks,
			HasPassword:  len(u.PasswordHash) > 0,
			WebhookURL:   u.WebhookURL,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(myURLsResponse{URLs: out})
}

// parsePosInt parses a positive integer query parameter, falling back to
// def if missing/invalid and clamping at max. Centralised so listing
// endpoints (and any future paginated endpoints) share the same parsing
// behaviour.
func parsePosInt(raw string, def, max int) int {
	if raw == "" {
		return def
	}
	n := 0
	for _, c := range raw {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
		if n > max {
			return max
		}
	}
	if n <= 0 {
		return def
	}
	return n
}
