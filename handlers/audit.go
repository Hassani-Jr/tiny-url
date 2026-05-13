package handlers

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net/http"

	"tiny-url/models"
	"tiny-url/services"
)

// AuditHandler serves GET /api/audit. Operator-only by design — the
// log contains every state-changing action including which API key
// holder did what. Reuses METRICS_TOKEN as the gating credential so
// operators don't have to manage yet another secret; the metrics
// endpoint and the audit log are both "ops visibility" surfaces with
// the same trust posture.
//
// When METRICS_TOKEN is unset (the default) the endpoint is OPEN.
// Operators who put the binary on a private network and skip the
// token can still query audit history without a second config; those
// who care set the token and both surfaces lock down together.
type AuditHandler struct {
	storage      services.Store
	expectedHash []byte // sha256 of metricsToken; empty hash → endpoint open
	maxLimit     int
}

// NewAuditHandler hashes metricsToken at construction so the constant-
// time compare on every request doesn't re-hash. Empty metricsToken
// produces an empty hash, which the auth check special-cases to "no
// auth required".
func NewAuditHandler(storage services.Store, metricsToken string) *AuditHandler {
	var h []byte
	if metricsToken != "" {
		sum := sha256.Sum256([]byte(metricsToken))
		h = sum[:]
	}
	return &AuditHandler{storage: storage, expectedHash: h, maxLimit: 500}
}

type auditResponse struct {
	Events []models.AuditEvent `json:"events"`
}

func (h *AuditHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		writeError(w, http.StatusUnauthorized, "missing or invalid operator token")
		return
	}
	limit := parsePosInt(r.URL.Query().Get("limit"), 50, h.maxLimit)
	offset := parsePosInt(r.URL.Query().Get("offset"), 0, 1<<30)

	events, err := h.storage.RecentAuditEvents(limit, offset)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(auditResponse{Events: events})
}

// authorized returns true when the request presents the configured
// operator token, or when no token is configured at all. Constant-
// time compare prevents a one-byte-at-a-time timing leak of the
// stored hash.
func (h *AuditHandler) authorized(r *http.Request) bool {
	if len(h.expectedHash) == 0 {
		return true
	}
	_, got := extractBearer(r)
	if got == nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, h.expectedHash) == 1
}
