package services

import (
	"net"
	"testing"
)

// TestGeoIPPlaceholderIsNoop confirms the committed placeholder mmdb
// (zero bytes) does not break startup and that Country() returns ""
// for every input. This guards against a refactor that accidentally
// makes the embedded path mandatory: production builds with the real
// MaxMind file will return real country codes, but the in-repo build
// must keep working without it.
func TestGeoIPPlaceholderIsNoop(t *testing.T) {
	if len(embeddedGeoIP) != 0 {
		t.Skip("embedded mmdb is non-empty — likely a real GeoLite2 file is in place. The placeholder test only applies to the no-op fallback.")
	}
	g := NewGeoIP()
	for _, ip := range []net.IP{
		net.ParseIP("8.8.8.8"),
		net.ParseIP("1.1.1.1"),
		net.ParseIP("2606:4700:4700::1111"),
	} {
		if cc := g.Country(ip); cc != "" {
			t.Errorf("placeholder geoip returned %q for %s, want empty", cc, ip)
		}
	}
	// Nil and invalid inputs must not panic.
	if cc := g.Country(nil); cc != "" {
		t.Errorf("Country(nil) = %q, want empty", cc)
	}
	if err := g.Close(); err != nil {
		t.Errorf("Close error = %v", err)
	}
}

// TestGeoIPNilReceiver makes sure callers can use a nil *GeoIP without
// guards — handlers pass cfg.GeoIP through unconditionally in places.
func TestGeoIPNilReceiver(t *testing.T) {
	var g *GeoIP
	if cc := g.Country(net.ParseIP("8.8.8.8")); cc != "" {
		t.Errorf("nil receiver Country() = %q, want empty", cc)
	}
	if err := g.Close(); err != nil {
		t.Errorf("nil receiver Close() = %v, want nil", err)
	}
}
