package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"tiny-url/services"
)

// ReadyHandler reports whether the service is ready to take traffic. Unlike
// /healthz it pings the storage backend, so a database outage drains traffic
// at the load balancer instead of being absorbed silently. Probe budget is
// short — a slow/locked DB should fail readiness rather than block the
// probe up to the request WriteTimeout.
type ReadyHandler struct {
	store   services.Store
	timeout time.Duration
}

func NewReadyHandler(store services.Store, timeout time.Duration) *ReadyHandler {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &ReadyHandler{store: store, timeout: timeout}
}

func (h *ReadyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	w.Header().Set("Content-Type", "application/json")
	if err := h.store.Ping(ctx); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "not_ready",
			"error":  err.Error(),
		})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
}
