package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"tiny-url/models"
	"tiny-url/services"
)

// PatchHandler updates the destination URL and/or expiration of an existing
// short code. Owner-token gated, like DELETE and analytics. Mirrors the
// shorten handler's validation rules so a PATCH cannot smuggle a deny-listed
// or SSRF host past the create-time guards.
type PatchHandler struct {
	storage              services.Store
	maxExpirationMinutes int
	maxBodyBytes         int64
	denyList             *services.DenyList
}

func NewPatchHandler(storage services.Store, maxExpirationMinutes int, maxBodyBytes int64, denyList *services.DenyList) *PatchHandler {
	return &PatchHandler{
		storage:              storage,
		maxExpirationMinutes: maxExpirationMinutes,
		maxBodyBytes:         maxBodyBytes,
		denyList:             denyList,
	}
}

// patchRequest mirrors ShortenRequest but uses pointer fields so we can tell
// "field omitted from JSON" apart from "field set to zero value":
//
//   - URL=nil            → leave destination URL unchanged
//   - URL=""             → invalid (rejected); empty replacement makes no sense
//   - ExpirationMins=nil → leave expiration unchanged
//   - ExpirationMins=0   → REMOVE expiration (URL becomes never-expiring)
//   - ExpirationMins>0   → set expiration to N minutes from now
//   - Tags=nil           → leave tags unchanged
//   - Tags=[]            → clear all tags
//   - MaxClicks=nil      → leave cap unchanged
//   - MaxClicks=0        → REMOVE cap (URL becomes unlimited)
//   - MaxClicks>0        → set new cap. Rejected if <= current click_count
//     to avoid silently making the URL instantly Gone.
//   - Password=nil       → leave password unchanged
//   - Password=""        → REMOVE password
//   - Password="..."     → set / replace password
type patchRequest struct {
	URL            *string   `json:"url"`
	ExpirationMins *int      `json:"expiration_mins"`
	Tags           *[]string `json:"tags"`
	MaxClicks      *int64    `json:"max_clicks"`
	Password       *string   `json:"password"`
	// WebhookURL=nil  → leave alone
	// WebhookURL=""   → clear webhook + secret
	// WebhookURL=URL  → set new URL; if `webhook_rotate_secret` is true OR
	//                   the URL is being newly added (was empty before), a
	//                   fresh secret is generated and returned.
	WebhookURL    *string `json:"webhook_url"`
	RotateWebhook bool    `json:"webhook_rotate_secret"`
	// Destinations=nil  → leave alone
	// Destinations=[]   → clear pool, revert to single-destination via OriginalURL
	// Destinations=...  → replace whole pool, all entries validated like the primary URL
	Destinations *[]models.Destination `json:"destinations"`
}

func (h *PatchHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	if code == "" {
		writeError(w, http.StatusBadRequest, "Short code is required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, h.maxBodyBytes)

	var req patchRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.URL == nil && req.ExpirationMins == nil && req.Tags == nil && req.MaxClicks == nil && req.Password == nil && req.WebhookURL == nil && !req.RotateWebhook && req.Destinations == nil {
		writeError(w, http.StatusBadRequest, "Provide at least one of url, expiration_mins, tags, max_clicks, password, webhook_url, destinations")
		return
	}

	mapping, err := h.storage.Get(code)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrNotFound):
			http.NotFound(w, r)
		case errors.Is(err, services.ErrExpired):
			w.WriteHeader(http.StatusGone)
			_, _ = w.Write([]byte("This URL has expired"))
		default:
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	if !authorizeAccess(r, mapping, h.storage) {
		writeError(w, http.StatusUnauthorized, "missing or invalid admin token")
		return
	}

	newURL := ""
	if req.URL != nil {
		if *req.URL == "" {
			writeError(w, http.StatusBadRequest, "url must be non-empty when provided")
			return
		}
		if err := services.ValidateDestinationURL(*req.URL, h.denyList); err != nil {
			writeError(w, http.StatusBadRequest, validationMessage(err))
			return
		}
		newURL = *req.URL
	}

	var (
		newExpiresAt    *time.Time
		clearExpiration bool
	)
	if req.ExpirationMins != nil {
		mins := *req.ExpirationMins
		switch {
		case mins < 0:
			writeError(w, http.StatusBadRequest, "expiration_mins must be non-negative")
			return
		case mins == 0:
			clearExpiration = true
		default:
			if mins > h.maxExpirationMinutes {
				mins = h.maxExpirationMinutes
			}
			t := time.Now().Add(time.Duration(mins) * time.Minute)
			newExpiresAt = &t
		}
	}

	patchFields := services.UpdateFields{
		ExpiresAt:       newExpiresAt,
		ClearExpiration: clearExpiration,
	}
	if newURL != "" {
		patchFields.OriginalURL = &newURL
	}

	if req.Tags != nil {
		normalized, err := services.NormalizeTags(*req.Tags)
		if err != nil {
			writeError(w, http.StatusBadRequest, tagsMessage(err))
			return
		}
		// Normalize a nil result from a non-nil request back to []string{}
		// so the store sees "clear all tags" instead of "leave alone".
		if normalized == nil {
			normalized = []string{}
		}
		patchFields.Tags = &normalized
	}

	if req.MaxClicks != nil {
		newCap := *req.MaxClicks
		if newCap < 0 {
			writeError(w, http.StatusBadRequest, "max_clicks must be non-negative")
			return
		}
		// Rejecting a cap that's already met avoids the surprising "I just
		// patched my URL and now it's Gone" UX. Owners who really want to
		// retire a URL should DELETE it.
		if newCap > 0 && newCap <= mapping.ClickCount {
			writeError(w, http.StatusBadRequest, "max_clicks must exceed current click_count")
			return
		}
		patchFields.MaxClicks = &newCap
	}

	if req.Password != nil {
		if *req.Password == "" {
			patchFields.ClearPassword = true
		} else {
			hash, salt, err := hashPassword(*req.Password)
			if err != nil {
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			patchFields.PasswordHash = hash
			patchFields.PasswordSalt = salt
		}
	}

	// New secret returned in the response. Only populated when one was
	// actually generated (new webhook or explicit rotate), so the response
	// stays empty on every other PATCH.
	var newWebhookSecret []byte
	if req.WebhookURL != nil {
		switch {
		case *req.WebhookURL == "":
			patchFields.ClearWebhook = true
		default:
			if err := services.ValidateDestinationURL(*req.WebhookURL, h.denyList); err != nil {
				writeError(w, http.StatusBadRequest, "webhook_url: "+validationMessage(err))
				return
			}
			patchFields.WebhookURL = req.WebhookURL
			// Generate a new secret when the webhook is being newly added
			// (previous mapping had none) OR when the caller explicitly
			// asked to rotate it. Otherwise leave the existing secret in
			// place — same URL, same key.
			if len(mapping.WebhookSecret) == 0 || req.RotateWebhook {
				secret, gerr := generateWebhookSecret()
				if gerr != nil {
					http.Error(w, "Internal server error", http.StatusInternalServerError)
					return
				}
				patchFields.WebhookSecret = secret
				newWebhookSecret = secret
			} else {
				// Preserve existing secret: pass it back into the store
				// so the URL update doesn't accidentally null it out.
				patchFields.WebhookSecret = mapping.WebhookSecret
			}
		}
	}
	if req.Destinations != nil {
		dests, derr := services.ValidateDestinations(*req.Destinations, h.denyList)
		if derr != nil {
			writeError(w, http.StatusBadRequest, "destinations: "+destinationsMessage(derr))
			return
		}
		// nil-vs-empty: a non-nil request with a validated nil result
		// means the caller asked to CLEAR the pool. Normalize so the
		// store sees a real (empty) slice instead of "leave alone".
		if dests == nil {
			dests = []models.Destination{}
		}
		patchFields.Destinations = &dests
	}

	if req.RotateWebhook && req.WebhookURL == nil {
		// Rotate without changing the URL. Requires an existing webhook.
		if mapping.WebhookURL == "" {
			writeError(w, http.StatusBadRequest, "webhook_rotate_secret requires an existing webhook_url")
			return
		}
		secret, gerr := generateWebhookSecret()
		if gerr != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		existingURL := mapping.WebhookURL
		patchFields.WebhookURL = &existingURL
		patchFields.WebhookSecret = secret
		newWebhookSecret = secret
	}

	if err := h.storage.Update(code, patchFields); err != nil {
		if errors.Is(err, services.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Re-read so the response reflects what was actually persisted (includes
	// upstream caps applied above).
	updated, err := h.storage.Get(code)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	// Audit: list the fields that were actually present in the PATCH
	// body so an operator reading the log can see "url changed but
	// expiration didn't" without diffing rows. We send only the
	// list of field NAMES — actual values would leak the new
	// password / webhook secret if those were included.
	changed := []string{}
	if req.URL != nil {
		changed = append(changed, "url")
	}
	if req.ExpirationMins != nil {
		changed = append(changed, "expiration_mins")
	}
	if req.Tags != nil {
		changed = append(changed, "tags")
	}
	if req.MaxClicks != nil {
		changed = append(changed, "max_clicks")
	}
	if req.Password != nil {
		changed = append(changed, "password")
	}
	if req.WebhookURL != nil {
		changed = append(changed, "webhook_url")
	}
	if req.RotateWebhook {
		changed = append(changed, "webhook_rotate_secret")
	}
	if req.Destinations != nil {
		changed = append(changed, "destinations")
	}
	metaBytes, _ := json.Marshal(map[string]any{"fields": changed})
	actorKind, actorID := resolveActor(r, mapping, h.storage)
	logAuditBestEffort(h.storage, models.AuditEvent{
		ActorKind:  actorKind,
		ActorID:    actorID,
		Action:     models.AuditActionURLPatch,
		TargetKind: "url",
		TargetID:   code,
		Metadata:   string(metaBytes),
		RequestID:  requestIDFromContext(r),
	})

	resp := map[string]any{
		"short_code":   updated.ID,
		"original_url": updated.OriginalURL,
		"expires_at":   updated.ExpiresAt,
		"tags":         updated.Tags,
		"max_clicks":   updated.MaxClicks,
		"has_password": len(updated.PasswordHash) > 0,
		"webhook_url":  updated.WebhookURL,
		"destinations": updated.Destinations,
	}
	// Only attach the secret when one was generated on this PATCH — this
	// is the only time the plaintext key leaves the server, mirroring
	// the admin_token contract.
	if len(newWebhookSecret) > 0 {
		resp["webhook_secret"] = encodeWebhookSecret(newWebhookSecret)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
