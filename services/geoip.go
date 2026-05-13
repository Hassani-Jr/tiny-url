package services

import (
	_ "embed"
	"log/slog"
	"net"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

// embeddedGeoIP holds the bytes baked in at build time from
// services/geoipdata/GeoLite2-Country.mmdb. The repo ships a zero-byte
// placeholder so the build never fails; operators replace it with the
// real MaxMind GeoLite2-Country.mmdb before producing release binaries
// (see services/geoipdata/README.md).
//
//go:embed geoipdata/GeoLite2-Country.mmdb
var embeddedGeoIP []byte

// GeoIP resolves a client IP to an ISO-3166-1 alpha-2 country code.
// When the embedded database is the zero-byte placeholder (or otherwise
// unparseable), the value returned by NewGeoIP returns "" from every
// Country() call — the rest of the click pipeline still works, country
// just stays empty.
type GeoIP struct {
	reader *maxminddb.Reader
	// lookup is the per-IP function. With a real DB this is reader.Lookup
	// wrapped to extract Country.IsoCode; with no DB it's a noop returning
	// "". Hoisting it into a field avoids a nil-check on every redirect.
	lookup func(ip net.IP) string
}

// geoipRecord matches the subset of the GeoLite2-Country schema we care
// about. The maxminddb library decodes by struct tags into Go values
// directly, so we don't need to walk the raw record.
type geoipRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// NewGeoIP loads the embedded mmdb. Returns a GeoIP whose Country method
// always reports "" when the placeholder is in place — log line at
// startup makes the state visible to operators.
func NewGeoIP() *GeoIP {
	g := &GeoIP{lookup: func(net.IP) string { return "" }}
	if len(embeddedGeoIP) == 0 {
		slog.Info("geoip disabled (placeholder GeoLite2-Country.mmdb present); see services/geoipdata/README.md")
		return g
	}
	reader, err := maxminddb.FromBytes(embeddedGeoIP)
	if err != nil {
		slog.Warn("geoip: failed to parse embedded mmdb, country enrichment disabled", "err", err)
		return g
	}
	// Sanity: report what we loaded so operators can confirm the build
	// picked up the right file. BuildTime is seconds-since-epoch — fine
	// to log raw; the actual age semantics are documented by MaxMind.
	md := reader.Metadata
	slog.Info("geoip loaded",
		"db_type", md.DatabaseType,
		"build_epoch", md.BuildEpoch,
		"node_count", md.NodeCount)
	g.reader = reader
	g.lookup = newReaderLookup(reader)
	return g
}

// newReaderLookup wraps the parsed reader into a function that performs
// the standard "look up IP, extract iso_code, swallow miss" flow. Errors
// (malformed IP, lookup miss) all collapse to "" so callers don't need
// to handle multiple failure modes — the country is metadata, not a
// load-bearing field.
func newReaderLookup(reader *maxminddb.Reader) func(net.IP) string {
	// The reader is safe for concurrent use, but Lookup allocates a fresh
	// record each call. Sync.Pool the record struct to keep the GC
	// overhead off the hot redirect path on busy services.
	var pool = sync.Pool{New: func() any { return new(geoipRecord) }}
	return func(ip net.IP) string {
		if ip == nil {
			return ""
		}
		rec := pool.Get().(*geoipRecord)
		defer func() {
			rec.Country.ISOCode = ""
			pool.Put(rec)
		}()
		if err := reader.Lookup(ip, rec); err != nil {
			return ""
		}
		return rec.Country.ISOCode
	}
}

// Country returns the ISO-3166-1 alpha-2 country code for ip, or "" when
// the IP isn't in the database, the database isn't loaded, or ip is nil.
// Safe for concurrent use.
func (g *GeoIP) Country(ip net.IP) string {
	if g == nil {
		return ""
	}
	return g.lookup(ip)
}

// Close releases resources held by the underlying reader. Idempotent.
func (g *GeoIP) Close() error {
	if g == nil || g.reader == nil {
		return nil
	}
	return g.reader.Close()
}
