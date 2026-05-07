package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds runtime configuration loaded from environment variables.
type Config struct {
	BaseURL              string
	Addr                 string
	TLSCertFile          string
	TLSKeyFile           string
	MaxExpirationMinutes int
	MaxBodyBytes         int64
	WriteRatePerMin      int
	ReadRatePerMin       int
	TrustProxy           bool
	CleanupInterval      time.Duration
	ShutdownTimeout      time.Duration
	// ShutdownDrain is a sleep window between SIGTERM and the actual
	// server.Shutdown call. Load balancers and service-mesh sidecars often
	// take several seconds to propagate the deregistration; without this
	// pause, in-flight requests during a deploy hit a closed listener and
	// produce 5xx blips. 0 disables — useful for tests.
	ShutdownDrain  time.Duration
	StorageBackend string // "memory" (default) or "sqlite"
	SQLitePath     string
	// DenyHosts is a comma-separated list of hostnames to refuse as
	// destination URLs. Subdomains of each entry are also blocked.
	DenyHosts []string
	// DenyHostsFile is an optional path to a text file with one host per
	// line (blank/'#' lines ignored). Merged with DenyHosts.
	DenyHostsFile string
	// LogClickIP, when true, stores a salted SHA-256 hash of the client IP
	// on each click event. Default off for privacy; turn on for unique-
	// visitor counting.
	LogClickIP bool
	// ClickIPSalt seeds the IP hash. Empty → random per-process salt;
	// uniqueness counts then reset across restarts. Set this to a long
	// random string to keep visitor IDs stable across deploys.
	ClickIPSalt string
	// ClickRetentionDays bounds how long click_events rows are kept by the
	// SQLite cleanup goroutine. Defaults to 90 days so the table doesn't
	// grow unbounded on a busy install — operators who want infinite
	// retention can opt in with CLICK_RETENTION_DAYS=0. The memory backend
	// has its own per-code FIFO cap and ignores this setting.
	ClickRetentionDays int
	// MetricsToken, when non-empty, gates GET /metrics behind a bearer
	// token check. Empty (the default) leaves /metrics open — fine if the
	// endpoint is firewalled or only reachable on a private network.
	MetricsToken string
}

// Load reads configuration from environment variables, falling back to safe defaults.
func Load() Config {
	return Config{
		BaseURL:              getEnv("BASE_URL", "http://localhost:8080"),
		Addr:                 ":" + getEnv("PORT", "8080"),
		TLSCertFile:          os.Getenv("TLS_CERT_FILE"),
		TLSKeyFile:           os.Getenv("TLS_KEY_FILE"),
		MaxExpirationMinutes: getEnvInt("MAX_EXPIRATION_MINUTES", 525600), // 1 year
		MaxBodyBytes:         int64(getEnvInt("MAX_BODY_BYTES", 4096)),
		WriteRatePerMin:      getEnvInt("WRITE_RATE_PER_MIN", 10),
		ReadRatePerMin:       getEnvInt("READ_RATE_PER_MIN", 120),
		TrustProxy:           os.Getenv("TRUST_PROXY") == "true",
		CleanupInterval:      time.Duration(getEnvInt("CLEANUP_INTERVAL_MINS", 5)) * time.Minute,
		ShutdownTimeout:      time.Duration(getEnvInt("SHUTDOWN_TIMEOUT_SECS", 10)) * time.Second,
		ShutdownDrain:        time.Duration(getEnvInt("SHUTDOWN_DRAIN_SECS", 5)) * time.Second,
		StorageBackend:       getEnv("STORAGE_BACKEND", "memory"),
		SQLitePath:           getEnv("SQLITE_PATH", "tiny-url.db"),
		DenyHosts:            splitCSV(os.Getenv("DENY_HOSTS")),
		DenyHostsFile:        os.Getenv("DENY_HOSTS_FILE"),
		LogClickIP:           os.Getenv("CLICK_LOG_IP") == "true",
		ClickIPSalt:          os.Getenv("CLICK_IP_SALT"),
		ClickRetentionDays:   getEnvInt("CLICK_RETENTION_DAYS", 90),
		MetricsToken:         os.Getenv("METRICS_TOKEN"),
	}
}

// splitCSV trims whitespace and drops empty entries. Helper for env vars
// that take comma-separated lists.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// TLSEnabled reports whether both certificate and key paths are configured.
func (c Config) TLSEnabled() bool {
	return c.TLSCertFile != "" && c.TLSKeyFile != ""
}

// ValidateBaseURL rejects BASE_URL values that would poison every API
// response. The base URL is concatenated into ShortURL and the QR target,
// so a misconfigured "javascript:" or "//evil.com" would emit short links
// that execute scripts when clicked. Operators can still misconfigure to a
// different valid host, but at least the scheme is enforced.
func ValidateBaseURL(raw string) error {
	if raw == "" {
		return errors.New("BASE_URL must not be empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("BASE_URL is not a valid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("BASE_URL scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("BASE_URL must include a host")
	}
	return nil
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getEnvInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		slog.Warn("config: invalid integer, using default", "key", key, "value", v, "default", def)
		return def
	}
	return n
}
