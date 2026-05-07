package services

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"regexp"
	"strings"
	"sync"
)

// processSalt is the per-process secret mixed into IP hashes. Set explicitly
// at startup via SetClickSalt, otherwise random. With a random salt the IP
// space cannot be rainbow-tabled even if the click log leaks; the tradeoff
// is unique-visitor counts reset across restarts. Operators who need stable
// uniqueness across deploys set CLICK_IP_SALT to a long random string.
var (
	processSalt   []byte
	processSaltMu sync.RWMutex
)

// SetClickSalt installs the IP-hash salt. Empty input → random per-process
// salt. Idempotent at startup; tests call it directly to set a fixed salt.
//
// NOTE: processSalt is package-global. Tests that call SetClickSalt and then
// rely on the value MUST NOT use t.Parallel() with each other — a parallel
// test in the same package would see the wrong salt. The mutex below makes
// the read/write race-free, but ordering across goroutines is still up to
// the caller.
func SetClickSalt(salt string) {
	processSaltMu.Lock()
	defer processSaltMu.Unlock()
	if salt != "" {
		processSalt = []byte(salt)
		return
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	processSalt = b
	slog.Warn("CLICK_IP_SALT not set; using random per-process salt — unique-visitor counts will reset on restart")
}

// HashIP returns hex(SHA-256(salt || ip)). Empty input yields "". The hash
// is intentionally fast (single SHA-256, not a KDF) — the threat model is
// "leaked DB without salt", which a single hash with a 128-bit secret salt
// already defeats. A KDF would burn CPU on every redirect for no extra
// security.
func HashIP(ip string) string {
	if ip == "" {
		return ""
	}
	processSaltMu.RLock()
	salt := processSalt
	processSaltMu.RUnlock()
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(ip))
	return hex.EncodeToString(h.Sum(nil))
}

// MaxRefererLength caps stored Referer values; modern browsers default to
// origin-only Referer and 512 chars covers any reasonable URL we'd see in
// practice while keeping the click log small.
const MaxRefererLength = 512

func TruncateReferer(r string) string {
	if len(r) > MaxRefererLength {
		return r[:MaxRefererLength]
	}
	return r
}

// UA classification is intentionally coarse. Storing raw UA strings would
// re-introduce the fingerprinting and targeting concerns we removed when
// we moved off of "log everything"; storing a 5-bucket label gives operators
// "what fraction of clicks are bots" without exposing client details.
var (
	uaBotRE    = regexp.MustCompile(`(?i)bot|crawler|spider|scraper|slurp|duckduckbot|baiduspider|yandexbot|sogou|exabot|ia_archiver|curl|wget|python-requests`)
	uaTabletRE = regexp.MustCompile(`(?i)iPad|tablet`)
	uaMobileRE = regexp.MustCompile(`(?i)Android.*Mobile|iPhone|iPod|Windows Phone|Mobile Safari|Opera Mini`)
)

func ClassifyUserAgent(ua string) string {
	if ua == "" {
		return "unknown"
	}
	switch {
	case uaBotRE.MatchString(ua):
		return "bot"
	case uaTabletRE.MatchString(ua):
		return "tablet"
	case uaMobileRE.MatchString(ua):
		return "mobile"
	case strings.Contains(strings.ToLower(ua), "mozilla"):
		return "desktop"
	default:
		return "unknown"
	}
}
