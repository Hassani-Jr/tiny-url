package handlers

import (
	"errors"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"sync/atomic"

	"tiny-url/services"
)

// BadgeHandler renders an embeddable "clicks: N" SVG, shields.io-style.
// Unauthenticated by design — the click count is the same data the
// dashboard owner could already display, and the threat model decided that
// exposing it for any known short code is acceptable in exchange for the
// "embed in a blog" use case.
//
// Caches aggressively (60 s public) so a popular embed doesn't hammer the
// service with repeat requests.
type BadgeHandler struct {
	storage services.Store
}

func NewBadgeHandler(storage services.Store) *BadgeHandler {
	return &BadgeHandler{storage: storage}
}

func (h *BadgeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Path is GET /api/badge/{code}.svg — strip the .svg suffix that is
	// captured by the {code} pattern so we accept "abc123.svg" as the
	// path token but use "abc123" to look up the mapping.
	rawCode := r.PathValue("code")
	code := rawCode
	if len(code) > 4 && code[len(code)-4:] == ".svg" {
		code = code[:len(code)-4]
	}
	if code == "" {
		http.NotFound(w, r)
		return
	}

	mapping, err := h.storage.Get(code)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrNotFound):
			http.NotFound(w, r)
		case errors.Is(err, services.ErrExpired):
			// 410 with an empty body is fine; embedders will see a broken
			// image and replace it on their side.
			w.WriteHeader(http.StatusGone)
		default:
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	count := atomic.LoadInt64(&mapping.ClickCount)
	svg := renderBadge(count)

	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	// Public: any cache may store. 60 s lets a chatty README hit cache
	// instead of the redirect handler, with a small staleness window.
	w.Header().Set("Cache-Control", "public, max-age=60")
	_, _ = w.Write([]byte(svg))
}

// renderBadge returns a shields.io-shaped SVG. Two pills: a dark "clicks"
// label on the left, a green count on the right. Width is computed from
// the digit count so big numbers don't clip.
func renderBadge(count int64) string {
	const labelText = "clicks"
	// Approximate text widths (DejaVu Sans 11px). Tuned so the result
	// looks visually balanced rather than mathematically precise.
	labelW := 6*len(labelText) + 10 // ~46
	countStr := strconv.FormatInt(count, 10)
	countW := 8*len(countStr) + 10
	if countW < 24 {
		countW = 24
	}
	totalW := labelW + countW
	labelMid := labelW / 2
	countMid := labelW + countW/2

	// Inline SVG, no external font references — survives CSP `default-src 'self'`
	// when embedded by readers via <img src="...">.
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="20" role="img" aria-label="clicks: %s">
<linearGradient id="g" x2="0" y2="100%%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
<mask id="m"><rect width="%d" height="20" rx="3" fill="#fff"/></mask>
<g mask="url(#m)">
<rect width="%d" height="20" fill="#555"/>
<rect x="%d" width="%d" height="20" fill="#10b981"/>
<rect width="%d" height="20" fill="url(#g)"/>
</g>
<g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
<text x="%d" y="14">%s</text>
<text x="%d" y="14">%s</text>
</g>
</svg>`, totalW, html.EscapeString(countStr),
		totalW,
		labelW,
		labelW, countW,
		totalW,
		labelMid, labelText,
		countMid, html.EscapeString(countStr))
}
