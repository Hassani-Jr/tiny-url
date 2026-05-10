package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"tiny-url/services"
)

// StreamHandler is a Server-Sent Events endpoint that pushes click events
// for a single short code to an authenticated client. Same owner-token
// gate as analytics — the click stream contains the same data as the
// click event log.
//
// The browser cannot set Authorization headers on the EventSource API,
// so the dashboard uses fetch() with a streaming body reader. Both work
// against this handler unchanged because we just emit standard SSE.
type StreamHandler struct {
	storage   services.Store
	stream    *services.ClickStream
	heartbeat time.Duration
}

func NewStreamHandler(storage services.Store, stream *services.ClickStream) *StreamHandler {
	return &StreamHandler{
		storage:   storage,
		stream:    stream,
		heartbeat: 15 * time.Second,
	}
}

func (h *StreamHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	if code == "" {
		writeError(w, http.StatusBadRequest, "Short code is required")
		return
	}

	mapping, err := h.storage.Get(code)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrNotFound):
			http.NotFound(w, r)
		case errors.Is(err, services.ErrExpired):
			w.WriteHeader(http.StatusGone)
		default:
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	if !authorizeOwner(r, mapping.OwnerTokenHash) {
		writeError(w, http.StatusUnauthorized, "missing or invalid admin token")
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	// Disable nginx response buffering so events arrive in real time.
	// (Harmless when no proxy is in front.)
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	// Initial comment line opens the stream so the client knows we're alive
	// even before the first real event. Any line starting with ":" is a
	// SSE comment (ignored by the parser).
	_, _ = fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	sub := h.stream.Subscribe(code)
	defer sub.Close()

	heartbeat := time.NewTicker(h.heartbeat)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			// Client disconnected (tab closed, navigation, network drop).
			// defer sub.Close() removes us from the subscriber set.
			return
		case ev, ok := <-sub.C():
			if !ok {
				return
			}
			data, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			// One SSE event = lines "event: click", "data: <json>", and
			// a terminating blank line. Browsers parse the JSON in
			// EventSource.onmessage / our fetch-stream parser.
			if _, err := fmt.Fprintf(w, "event: click\ndata: %s\n\n", data); err != nil {
				return
			}
			flusher.Flush()
		case <-heartbeat.C:
			// SSE comment to keep proxies / browsers from idle-closing.
			if _, err := fmt.Fprint(w, ": heartbeat\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
