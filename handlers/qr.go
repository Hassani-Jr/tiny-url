package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"tiny-url/services"

	"github.com/skip2/go-qrcode"
)

// QRHandler renders a PNG QR code for the public short URL of a code.
// The endpoint is unauthenticated by design: the encoded value is the same
// short URL anyone with the code can already visit, so a QR adds no
// privilege and gating it would block legitimate sharing flows.
type QRHandler struct {
	storage services.Store
	baseURL string
}

func NewQRHandler(storage services.Store, baseURL string) *QRHandler {
	return &QRHandler{storage: storage, baseURL: baseURL}
}

func (h *QRHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	if code == "" {
		http.NotFound(w, r)
		return
	}

	if _, err := h.storage.Get(code); err != nil {
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

	target := h.baseURL + "/" + code
	png, err := qrcode.Encode(target, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "qr generation failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	// QR PNG is deterministic for a code (encodes the public short URL,
	// which never changes). Public + immutable lets shared caches absorb
	// repeat downloads and saves the qrcode.Encode CPU on every fetch.
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="qr-%s.png"`, code))
	_, _ = w.Write(png)
}
