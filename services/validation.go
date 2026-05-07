package services

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	MaxURLLength = 2048
	// dnsLookupTimeout caps how long the SSRF guard will wait on DNS. A slow
	// or hostile resolver would otherwise stall the request handler up to the
	// server's WriteTimeout and let an attacker pin goroutines by submitting
	// many shorten requests for hosts that resolve slowly.
	dnsLookupTimeout = 3 * time.Second
)

var (
	ErrInvalidURL        = errors.New("invalid URL")
	ErrInvalidScheme     = errors.New("URL must use http or https scheme")
	ErrURLTooLong        = errors.New("URL exceeds maximum length")
	ErrUserInfo          = errors.New("URL must not contain user credentials")
	ErrInvalidHost       = errors.New("URL has no resolvable host")
	ErrPrivateAddress    = errors.New("URL host resolves to a non-routable address")
	ErrInvalidCustomCode = errors.New("custom code must be alphanumeric (3-32 chars: letters, digits, '_' or '-')")
	ErrReservedCode      = errors.New("custom code is reserved")
)

// ValidateDestinationURL enforces the rules for a user-supplied destination URL.
// It rejects non-http(s) schemes, oversized URLs, embedded credentials, hosts
// on the operator-configured deny list, and any host that resolves to a
// loopback / private / link-local / multicast / CGNAT address — which blocks
// SSRF probes against internal services and cloud metadata endpoints. Errors
// wrap ErrPrivateAddress and include the IP category (loopback, private,
// link-local, …) in their message so logs and upstream tests can distinguish
// the rejection reason without exposing the raw target to API clients.
//
// The deny check runs BEFORE DNS resolution so operators don't pay a DNS
// round-trip for known-bad hosts and so error messages are actionable
// ("denied") rather than blamed on resolution.
//
// DNS resolution happens once here; an attacker-controlled resolver could in
// principle TOCTOU between this check and the actual redirect — that residual
// risk is documented and not currently mitigated (would require either a
// resolver-pinning hop or post-resolution dial-time enforcement).
//
// Pass deny=nil to skip the deny-list check (tests, or operators who haven't
// configured one).
func ValidateDestinationURL(raw string, deny *DenyList) error {
	if len(raw) > MaxURLLength {
		return ErrURLTooLong
	}

	u, err := url.Parse(raw)
	if err != nil {
		return ErrInvalidURL
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ErrInvalidScheme
	}
	if u.User != nil {
		return ErrUserInfo
	}

	host := u.Hostname()
	if deny.Contains(host) {
		return fmt.Errorf("%w: %s", ErrDeniedHost, host)
	}
	return ValidateHostAtRuntime(host)
}

// ValidateHostAtRuntime evaluates the host-resolution part of the SSRF check
// in isolation. It runs the same loopback / private / link-local / multicast /
// CGNAT guards as ValidateDestinationURL but skips scheme / length /
// userinfo / deny-list — those checks are stable across the lifetime of a
// stored URL or are evaluated separately at redirect time.
//
// The redirect handler calls this before issuing every 302. That closes the
// DNS-rebinding window where an attacker validates with a public IP at create
// time, then flips DNS to 169.254.169.254 (or any private/loopback target)
// before clicks fire. The OS DNS cache absorbs most repeat lookups; an
// attacker-controlled domain with a 1-second TTL still re-resolves often
// enough that any rebind takes effect in seconds rather than instantly.
func ValidateHostAtRuntime(host string) error {
	if host == "" {
		return ErrInvalidHost
	}
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return fmt.Errorf("%w: loopback hostname %q", ErrPrivateAddress, host)
	}

	if ip := net.ParseIP(host); ip != nil {
		if cat := categorizeIP(ip); cat != "" {
			return fmt.Errorf("%w: %s address %s", ErrPrivateAddress, cat, ip)
		}
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), dnsLookupTimeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return ErrInvalidHost
	}
	for _, ip := range ips {
		if cat := categorizeIP(ip.IP); cat != "" {
			return fmt.Errorf("%w: host %q resolves to %s address %s", ErrPrivateAddress, host, cat, ip.IP)
		}
	}
	return nil
}

// categorizeIP returns a short label naming the reserved range an IP belongs
// to, or "" if the address is publicly routable. The label is included in the
// error message so operators can tell why an SSRF check fired.
func categorizeIP(ip net.IP) string {
	switch {
	case ip.IsLoopback():
		return "loopback"
	case ip.IsLinkLocalUnicast():
		return "link-local"
	case ip.IsMulticast():
		// IsMulticast covers IPv4 224.0.0.0/4 and IPv6 ff00::/8, so all
		// link-local-multicast and interface-local-multicast addresses fall
		// here too — labelling them under the more general "multicast"
		// matches what most users expect.
		return "multicast"
	case ip.IsPrivate():
		return "private"
	case ip.IsUnspecified():
		return "unspecified"
	}
	if ip4 := ip.To4(); ip4 != nil {
		// 100.64.0.0/10 — Carrier-grade NAT. Not covered by IsPrivate.
		if ip4[0] == 100 && ip4[1]&0xC0 == 64 {
			return "cgnat"
		}
	}
	return ""
}

var customCodeRegex = regexp.MustCompile(`^[A-Za-z0-9_-]{3,32}$`)

// reservedCodes are top-level path segments that already serve a purpose
// (API namespace, static assets, health probe, browser-prefetched files).
// Allowing them as custom aliases would shadow real routes or create
// confusion when someone debugs a 404.
var reservedCodes = map[string]bool{
	"api":         true,
	"static":      true,
	"healthz":     true,
	"favicon.ico": true,
	"robots.txt":  true,
}

// ValidateCustomCode enforces the format and reserved-word rules for
// user-supplied custom aliases. Reserved is checked first so codes like
// "favicon.ico" that contain disallowed characters still report the more
// informative reserved-word error rather than a generic format complaint.
func ValidateCustomCode(code string) error {
	if reservedCodes[strings.ToLower(code)] {
		return ErrReservedCode
	}
	if !customCodeRegex.MatchString(code) {
		return ErrInvalidCustomCode
	}
	return nil
}
