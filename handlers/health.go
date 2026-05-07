package handlers

import (
	"encoding/json"
	"net/http"
)

// HealthHandler exposes a cheap liveness signal at /healthz. It deliberately
// does not ping the storage backend — a real outage surfaces at /api/* with
// proper status codes, and a no-IO probe stays responsive even when the
// database is recovering.
type HealthHandler struct {
	backend string
}

func NewHealthHandler(backend string) *HealthHandler {
	return &HealthHandler{backend: backend}
}

func (h *HealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"storage": h.backend,
	})
}
