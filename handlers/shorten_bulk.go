package handlers

import (
	"encoding/json"
	"net/http"

	"tiny-url/models"
)

// BulkShortenHandler accepts an array of ShortenRequest items in a
// single round-trip and returns a parallel array of per-item results.
// Designed for migrations from another shortener — N round-trips
// against /api/shorten works but is wasteful when importing
// thousands of links, and the per-IP write rate limit makes it
// painful in practice.
//
// Items are processed independently: one bad URL fails its own item
// without rolling back successful neighbours. The response carries
// either `result` (the canonical ShortenResponse, same as the
// single-item endpoint) OR `error` per item, so the client can
// retry just the failed rows.
type BulkShortenHandler struct {
	shorten  *ShortenHandler
	maxItems int
}

// NewBulkShortenHandler wires the bulk endpoint to share validation
// and audit logic with the single-item handler. maxItems caps the
// per-request size; 50 is enough to make import practical without
// letting one request hog a worker for too long.
func NewBulkShortenHandler(shorten *ShortenHandler, maxItems int) *BulkShortenHandler {
	if maxItems <= 0 {
		maxItems = 50
	}
	return &BulkShortenHandler{shorten: shorten, maxItems: maxItems}
}

type bulkShortenRequest struct {
	Items []models.ShortenRequest `json:"items"`
}

type bulkShortenItemResult struct {
	Index  int                     `json:"index"`
	Result *models.ShortenResponse `json:"result,omitempty"`
	Error  *itemError              `json:"error,omitempty"`
}

type bulkShortenResponse struct {
	Created int                     `json:"created"`
	Failed  int                     `json:"failed"`
	Items   []bulkShortenItemResult `json:"items"`
}

func (h *BulkShortenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Only POST method is allowed")
		return
	}
	apiKeyID := h.shorten.detectAPIKey(r)

	// Bulk endpoint is allowed a bigger body than the single-item
	// endpoint because it carries N requests in one shot. 64KB caps
	// the worst case at ~1.3KB per item across the 50-item limit,
	// which is generous for the typical {url, tags, custom_code}
	// payload.
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req bulkShortenRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if len(req.Items) == 0 {
		writeError(w, http.StatusBadRequest, "items must not be empty")
		return
	}
	if len(req.Items) > h.maxItems {
		writeError(w, http.StatusBadRequest, "too many items in one request")
		return
	}

	reqID := requestIDFromContext(r)
	resp := bulkShortenResponse{Items: make([]bulkShortenItemResult, len(req.Items))}

	// Serial processing keeps the storage layer's invariants
	// straightforward (custom-code uniqueness depends on Exists+Set
	// being seen in order). The per-item PBKDF2 cost dominates anyway
	// when passwords are set; parallelism wouldn't help the common
	// migration use case.
	for i, item := range req.Items {
		result, ierr := h.shorten.shortenOne(item, apiKeyID, reqID)
		entry := bulkShortenItemResult{Index: i}
		if ierr != nil {
			entry.Error = ierr
			resp.Failed++
		} else {
			entry.Result = result
			resp.Created++
		}
		resp.Items[i] = entry
	}

	// Always 200 with per-item statuses. A 4xx on the outer response
	// would imply the whole request failed, but mixed success is the
	// expected case for migrations and would confuse clients.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
