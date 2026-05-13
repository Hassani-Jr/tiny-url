# Tiny URL Shortener

A secure, fast, and efficient URL shortener built with Go. Features include URL shortening, click analytics, URL expiration, custom aliases, QR code generation, and a clean web interface. Built with security-first design: SSRF protection, rate limiting, CSRF defense, and owner-token-gated analytics.

The full REST API is documented in [`static/openapi.yaml`](static/openapi.yaml) (OpenAPI 3.0); the running server also serves it at `/static/openapi.yaml` so tools like Postman / Insomnia / a Swagger UI can fetch it directly.

## Features

- **URL Shortening**: Generate short, unique codes for any URL with cryptographic randomness
- **Custom Aliases**: User-specified short codes (3-32 alphanumeric characters) with collision detection
- **Click Analytics**: Track click counts and access times (gated by owner token for privacy)
- **URL Expiration**: Optional time-limited URLs that expire after a specified duration
- **QR Code Generation**: Download PNG QR codes encoding the short URL
- **Web Interface**: Clean, responsive HTML frontend for easy URL shortening and analytics
- **REST API**: Full REST API for programmatic access
- **Security Features**: SSRF protection (IP validation), rate limiting per-IP, CSRF defense, security headers, bearer-token authentication
- **Persistence**: Optional SQLite backend for data retention across restarts; memory-only mode for ephemeral use
- **TLS Support**: HTTPS with HSTS header support
- **Graceful Shutdown**: Clean handling of SIGINT/SIGTERM with in-flight request completion
- **Background Cleanup**: Automatic removal of expired URLs
- **Owner Delete & Edit**: `DELETE /api/url/{code}` removes a short link; `PATCH /api/url/{code}` updates the destination URL and/or expiration. Both gated by the per-URL admin token.
- **Per-Click Event Log**: `GET /api/analytics/{code}/clicks` returns each click's timestamp, coarse device class, truncated Referer, and (optionally) a salted IP hash. Privacy-respecting by default — raw User-Agent is never stored.
- **Observability**: Structured (`slog`) logs with per-request `X-Request-ID` correlation; `/metrics` (expvar) and `/readyz` (storage-aware readiness) endpoints alongside `/healthz`

## Quick Start

### Prerequisites

- Go 1.25 or higher (uses `log/slog`, `embed`, and the 1.22+ pattern-routing mux)
- (Optional) SQLite for persistent storage (pure-Go driver, no additional dependencies)

### Installation

1. Clone or download this repository
2. Navigate to the project directory:
   ```bash
   cd tiny-url
   ```

3. Download dependencies:
   ```bash
   go mod download
   ```

4. Build the application:
   ```bash
   go build -o tiny-url.exe .
   ```

5. Run the server:
   ```bash
   ./tiny-url.exe
   ```
   Or run directly without building:
   ```bash
   go run .
   ```

6. Open your browser and visit:
   ```
   http://localhost:8080
   ```

By default, the server uses in-memory storage (data lost on restart) and listens on port `:8080`.

## Usage

### Web Interface

1. Open http://localhost:8080 in your browser
2. **Shorten Section**:
   - Enter a URL to shorten
   - (Optional) Specify a custom alias (3-32 alphanumeric characters, plus `_` and `-`)
   - (Optional) Set an expiration time in minutes
   - Click "Shorten URL"
   - Copy the shortened URL and share it
   - Download the QR code (encodes the short URL as PNG)
3. **Analytics Section**:
   - Enter a short code you created
   - View click count, original URL, creation time, last access, and status
   - Only the creator of the short code can view analytics (verified via owner token stored in browser localStorage)

### API Endpoints

#### Shorten a URL

```bash
curl -X POST http://localhost:8080/api/shorten \
  -H "Content-Type: application/json" \
  -H "X-Requested-With: XMLHttpRequest" \
  -d '{"url": "https://example.com"}'
```

Response (201 Created):
```json
{
  "short_code": "aBc123",
  "short_url": "http://localhost:8080/aBc123",
  "original_url": "https://example.com",
  "admin_token": "base64-encoded-32-byte-token"
}
```

The `admin_token` is used to access analytics. Store it securely if you need analytics access outside the browser.

#### Shorten with Custom Alias

```bash
curl -X POST http://localhost:8080/api/shorten \
  -H "Content-Type: application/json" \
  -H "X-Requested-With: XMLHttpRequest" \
  -d '{"url": "https://example.com", "custom_code": "my-link"}'
```

**Custom code requirements:**
- 3-32 characters
- Alphanumeric, underscore, hyphen only (`[A-Za-z0-9_-]`)
- Reserved words forbidden: `api`, `static`, `healthz`, `favicon.ico`, `robots.txt`
- Must be globally unique; returns 409 Conflict if already in use

Response (201 Created):
```json
{
  "short_code": "my-link",
  "short_url": "http://localhost:8080/my-link",
  "original_url": "https://example.com",
  "admin_token": "base64-encoded-32-byte-token"
}
```

#### Shorten with Expiration

```bash
curl -X POST http://localhost:8080/api/shorten \
  -H "Content-Type: application/json" \
  -H "X-Requested-With: XMLHttpRequest" \
  -d '{"url": "https://example.com", "expiration_mins": 60}'
```

Response (201 Created):
```json
{
  "short_code": "xYz789",
  "short_url": "http://localhost:8080/xYz789",
  "original_url": "https://example.com",
  "expires_at": "2026-04-29T23:00:00Z",
  "admin_token": "base64-encoded-32-byte-token"
}
```

**Expiration constraints:**
- Maximum 1 year (525,600 minutes) by default
- Configurable via `MAX_EXPIRATION_MINUTES` environment variable
- Expired URLs return 410 Gone

#### Access a Short URL

```bash
curl -L http://localhost:8080/aBc123
```

This will redirect to the original URL (302 Found) and increment the click counter. Returns 404 if the code doesn't exist, or 410 Gone if the URL has expired.

#### Get Analytics

Analytics requires an `admin_token` for authorization.

```bash
curl http://localhost:8080/api/analytics/aBc123 \
  -H "Authorization: Bearer <admin_token>"
```

Response (200 OK):
```json
{
  "short_code": "aBc123",
  "original_url": "https://example.com",
  "click_count": 42,
  "created_at": "2026-04-28T20:00:00Z",
  "last_accessed": "2026-04-28T22:30:00Z"
}
```

**Authorization:**
- Requires `Authorization: Bearer <token>` header with the admin token
- Returns 401 Unauthorized if token missing or invalid
- Returns 410 Gone if the URL has expired
- Only the creator (holder of the admin token) can access analytics

#### Download QR Code

```bash
curl http://localhost:8080/api/qr/aBc123 -o qr.png
```

Generates a PNG QR code encoding the short URL. No authentication required (the short URL is already public).

#### Update a Short URL (PATCH)

```bash
curl -X PATCH http://localhost:8080/api/url/aBc123 \
  -H "Content-Type: application/json" \
  -H "X-Requested-With: XMLHttpRequest" \
  -H "Authorization: Bearer <admin_token>" \
  -d '{"url": "https://newdestination.example", "expiration_mins": 1440}'
```

Both fields are optional; supply at least one. Pointer-typed JSON parsing distinguishes "field omitted" (no change) from "field set to zero":

| `expiration_mins` value | Effect |
|---|---|
| field omitted | leave expiration unchanged |
| `0` | **remove** expiration — URL becomes never-expiring |
| `> 0` | set expiration to N minutes from now (capped at `MAX_EXPIRATION_MINUTES`) |

Response: `200 OK` with the post-update `short_code` / `original_url` / `expires_at`. New destination URLs go through the same SSRF + deny-list checks as `POST /api/shorten`.

#### Get Per-Click Events

```bash
curl 'http://localhost:8080/api/analytics/aBc123/clicks?limit=50' \
  -H "Authorization: Bearer <admin_token>"
```

Response (200 OK):
```json
{
  "short_code": "aBc123",
  "count": 3,
  "events": [
    {
      "at": "2026-05-05T14:23:11Z",
      "ua_class": "mobile",
      "referer": "https://news.ycombinator.com/"
    },
    {
      "at": "2026-05-05T14:21:02Z",
      "ua_class": "desktop"
    },
    {
      "at": "2026-05-05T13:55:30Z",
      "ua_class": "bot",
      "ip_hash": "f3a1…"
    }
  ]
}
```

`ip_hash` is only present when `CLICK_LOG_IP=true`. Events are returned newest first, capped at the server-side maximum (default 200). The memory backend keeps the last 1000 events per code; the SQLite backend persists them subject to `CLICK_RETENTION_DAYS`.

#### Delete a Short URL

```bash
curl -X DELETE http://localhost:8080/api/url/aBc123 \
  -H "Authorization: Bearer <admin_token>"
```

Response: `204 No Content` on success.

**Authorization:**
- Requires `Authorization: Bearer <token>` header with the admin token
- Returns `401 Unauthorized` if token missing or invalid
- Returns `404 Not Found` if the code does not exist
- Returns `410 Gone` if the URL has already expired (it will be reaped by the cleanup goroutine)

#### Health Check

```bash
curl http://localhost:8080/healthz
```

Response (200 OK):
```json
{
  "status": "ok",
  "storage": "memory|sqlite"
}
```

Cheap liveness probe (does not ping database). Useful for Kubernetes or load balancer health checks.

#### Readiness Check

```bash
curl http://localhost:8080/readyz
```

Returns `200 OK` with `{"status":"ready"}` when the storage backend responds to a ping (2-second timeout). Returns `503 Service Unavailable` with the underlying error otherwise. Use this for Kubernetes `readinessProbe`; pair with `/healthz` as `livenessProbe`.

#### Metrics

```bash
curl http://localhost:8080/metrics
```

Returns the standard Go `expvar` JSON exposition. Includes:
- `http_requests_total` — map keyed by status class (`2xx`, `4xx`, `5xx`, …)
- `http_requests_route_total` — map keyed by `<matched ServeMux pattern>|<status_class>` (e.g., `"GET /{code}|2xx"`). Lets operators see which endpoint is hot or failing without parsing logs. Unmatched paths are deliberately not counted to keep an attacker from pinning unbounded keys with random URLs.
- `http_requests_in_flight` — current concurrent requests
- `panics_total` — every time the Recover middleware catches a handler panic. Alert on a sudden spike.
- standard runtime metrics (`memstats`, `cmdline`)

By default the endpoint is open — firewall it or scrape from a private network. Set `METRICS_TOKEN` to require `Authorization: Bearer <token>` on every scrape (Prometheus's `bearer_token_file` integrates cleanly). To switch from expvar to native Prometheus exposition, swap `middleware.GatedMetricsHandler(...)` in `main.go` for `promhttp.Handler()` from `github.com/prometheus/client_golang`.

#### Request Correlation

Every response carries an `X-Request-ID` header. Inbound `X-Request-ID` values are honored if present (≤64 chars); otherwise the server generates a 16-hex-char ID. The same ID appears in every structured log line for that request, so you can grep one ID across the log stream to follow a single request through middleware.

Each log line also includes a `route` field carrying the matched ServeMux pattern (`"GET /{code}"`, `"GET /api/analytics/{code}/clicks"`, …). Aggregating logs on `route` instead of `path` collapses every dynamic short-code request into one bucket, making "top routes" queries useful even at high traffic.

Successful (`<400`) hits to `/healthz`, `/readyz`, `/metrics`, and `/favicon.ico` are deliberately NOT logged — Kubernetes-style probes at 1Hz per pod would otherwise produce 120+ log lines per minute and drown out real request logs. Failures still log: a flood of `/readyz` 503s is exactly the signal you want surfaced. The Metrics middleware counts probes too, so dashboards remain accurate.

## Project Structure

```
tiny-url/
├── main.go                 # Application entry point, server setup, graceful shutdown
├── go.mod                  # Go module definition
├── go.sum                  # Module checksums
├── config/
│   └── config.go           # Environment variable configuration loader
├── models/
│   └── url.go              # Data models (URLMapping, ShortenRequest, ShortenResponse)
├── services/
│   ├── storage.go          # Store interface + MemoryStore implementation
│   ├── storage_sqlite.go   # SQLiteStore implementation (optional persistence)
│   ├── shortcode.go        # Short code generation with collision detection
│   └── validation.go       # URL destination + custom code validation (SSRF protection)
├── handlers/
│   ├── shorten.go          # POST /api/shorten handler (with custom codes + owner tokens)
│   ├── redirect.go         # GET /{code} handler (with click tracking)
│   ├── analytics.go        # GET /api/analytics/{code} handler (bearer-token gated)
│   ├── qr.go               # GET /api/qr/{code} handler (PNG QR code generation)
│   ├── health.go           # GET /healthz handler (liveness probe)
│   └── index.go            # GET / handler (serves index.html)
├── middleware/
│   ├── logging.go          # Request/response logging
│   ├── security.go         # Security headers (CSP, X-Frame-Options, HSTS, etc.)
│   ├── ratelimit.go        # Per-IP rate limiting with token bucket
│   └── csrf.go             # CSRF defense (X-Requested-With check)
└── static/
    ├── index.html          # Frontend UI with analytics section
    ├── app.js              # Frontend logic (API calls, owner token storage)
    └── style.css           # Styling
```

## Security Model

This application implements defense-in-depth security with multiple layers:

### SSRF (Server-Side Request Forgery) Protection

**Threat:** Attackers could request URLs pointing to internal networks or cloud metadata endpoints.

**Mitigation:** `ValidateDestinationURL()` in `services/validation.go`:
1. Validates scheme is `http` or `https` only
2. Validates URL length ≤ 2048 characters
3. Rejects URLs with embedded credentials (`user:pass@host`)
4. Resolves hostname to IP(s) and rejects:
   - Loopback addresses (127.0.0.0/8, ::1)
   - Private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
   - Link-local addresses (169.254.0.0/16, fe80::/10)
   - Multicast and unspecified ranges
   - CGNAT (100.64.0.0/10)
   - Cloud metadata endpoints (by hostname resolution)

**Runtime re-check (DNS rebinding):** the host validation runs three times in the URL's life cycle:

1. At creation (`POST /api/shorten`)
2. At update (`PATCH /api/url/{code}`)
3. **At every redirect (`GET /{code}`)** via `services.ValidateHostAtRuntime`

The redirect-time re-check is the load-bearing one against DNS rebinding: an attacker who registers `attacker.example`, points it at a public IP for validation, then flips the A record to `169.254.169.254` (cloud metadata) loses, because every click re-resolves and re-runs `categorizeIP`. The OS DNS cache absorbs the cost on hot URLs; an attacker-controlled domain with a 1-second TTL still re-resolves often enough that any rebind takes effect within seconds. Blocked redirects return `451 Unavailable for Legal Reasons`.

### Rate Limiting

**Threat:** Attackers could flood the server with requests causing DoS or resource exhaustion.

**Mitigation:** Per-IP token bucket rate limiting (`middleware/ratelimit.go`):
- **Writes** (POST /api/shorten): 10 requests per minute per IP (configurable via `WRITE_RATE_PER_MIN`)
- **Reads** (GET requests): 120 requests per minute per IP (configurable via `READ_RATE_PER_MIN`)
- Returns `429 Too Many Requests` with `Retry-After` header when exceeded
- Automatic cleanup of stale buckets to prevent memory leaks
- Respects `X-Forwarded-For` header when running behind a trusted reverse proxy (enable with `TRUST_PROXY=true`)

### CSRF (Cross-Site Request Forgery) Protection

**Threat:** Malicious websites could trick users into shortening URLs.

**Mitigation:** All POST requests to `/api/shorten` require the `X-Requested-With: XMLHttpRequest` header (`middleware/csrf.go`):
- Cannot be set by `<form>` or `<img>` tags cross-origin (requires CORS preflight which we reject)
- Standard browser fetch/XMLHttpRequest automatically sets this for same-origin requests
- Returns `403 Forbidden` if header missing

### Authentication & Authorization

**Threat:** Attackers could read analytics for URLs they didn't create.

**Mitigation:** Owner-token authentication (`handlers/analytics.go`):
- When creating a URL, server generates a 32-byte cryptographic random token (`crypto/rand`)
- Token is returned to client immediately (bearer token in `admin_token` field)
- Server stores SHA-256 hash of token in database/storage
- Analytics, delete, and patch endpoints require `Authorization: Bearer <token>` header
- Compares provided token against stored hash using `subtle.ConstantTimeCompare` (timing-safe)
- Returns `401 Unauthorized` if token missing or invalid
- Frontend stores token in `localStorage` keyed by short code for creator access only

**Token storage trust model — known limitation:** `localStorage` is readable by ANY same-origin JavaScript. The CSP (`script-src 'self'`) prevents injected external scripts from running, but two threats survive:

1. **A future XSS vulnerability** in the web UI (e.g., an unsanitized field rendered as HTML, or a vulnerable third-party script later added to the page) would let attacker JS enumerate every `tinyurl:token:*` entry and delete or edit the user's URLs.
2. **A malicious browser extension** with `*://*/*` host permissions can read `localStorage` of every site the user visits, including this one.

If your threat model includes either of those, **don't rely on the web UI for token storage**. Use the REST API directly and keep the token in a dedicated secret manager. The plaintext token is only shown once (in the `POST /api/shorten` response) — save it deliberately at that point.

This is a deliberate trade-off for a stateless service. Moving tokens to `Secure; HttpOnly; SameSite=Strict` cookies would defeat both threats but requires a server-side session model that the current architecture doesn't have.

### Security Headers

Middleware adds defensive HTTP headers (`middleware/security.go`):
- `X-Content-Type-Options: nosniff` — prevents MIME-sniffing attacks
- `X-Frame-Options: DENY` — prevents clickjacking
- `Referrer-Policy: no-referrer` — protects user privacy
- `Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self'` — restricts resource loading
- `Strict-Transport-Security: max-age=31536000; includeSubDomains` (only over HTTPS) — forces TLS

### Input Validation

- URLs validated via `ValidateDestinationURL()` (scheme, length, IP address ranges, deny-list)
- Custom codes validated via `ValidateCustomCode()` (regex `^[A-Za-z0-9_-]{3,32}$`, reserved words list)
- Expiration capped at configurable maximum (default 1 year = 525,600 minutes)
- Request bodies limited to 4096 bytes

### Host Deny-List (Abuse Defense)

**Threat:** Attackers shorten URLs pointing at known-phishing or malware-distribution hosts and use the redirector for laundering.

**Mitigation:** A configurable host deny-list, populated via `DENY_HOSTS` (CSV) and/or `DENY_HOSTS_FILE` (one host per line; blank and `#` lines ignored). Matching is case-insensitive and applies to subdomains, so `DENY_HOSTS=evil.com` blocks `evil.com`, `www.evil.com`, and any deeper subdomain. The file format tolerates the common feed conventions: `*.evil.com`, `.evil.com`, and `evil.com` are all equivalent.

The deny-list is checked at **two** points:
1. **Create time** (`POST /api/shorten`) — denied hosts return `400 Bad Request` with `URL host is not permitted`.
2. **Redirect time** (`GET /{code}`) — denied hosts return `451 Unavailable for Legal Reasons` with a "this short URL has been disabled" body. Existing short URLs stop resolving the moment a host is added to the list, without waiting for the cleanup goroutine.

The list is loaded at startup; restart the process after editing the file. For dynamic feed updates, run a sidecar that rewrites the file and `kill -HUP` (or in Kubernetes, restart the pod via a config-checksum annotation).

```bash
# Block a couple of hosts inline.
export DENY_HOSTS="evil.com,phishing.example,malware.test"

# Or maintain a list file.
cat > /etc/tiny-url/deny.txt <<'EOF'
# blocked-hosts feed, last updated 2026-05-05
evil.com
*.phishy.example
203.0.113.7
EOF
export DENY_HOSTS_FILE=/etc/tiny-url/deny.txt
```

### Graceful Shutdown

- Server listens for SIGINT/SIGTERM signals
- Stops accepting new connections, drains in-flight requests (10 second timeout)
- Storage backend closes cleanly (SQLite flushes and locks released)

## Configuration

All settings are loaded from environment variables with sensible defaults. No code modification needed.

| Environment Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | Port to listen on |
| `BASE_URL` | `http://localhost:8080` | Base URL for short links (e.g., `https://short.example.com`) |
| `STORAGE_BACKEND` | `memory` | Storage backend: `memory`, `sqlite`, or `postgres` |
| `SQLITE_PATH` | `tiny-url.db` | Path to SQLite database file (only used if `STORAGE_BACKEND=sqlite`) |
| `POSTGRES_DSN` | _(unset)_ | Postgres connection string (only used if `STORAGE_BACKEND=postgres`). Either URL form (`postgres://user:pw@host:5432/dbname?sslmode=require`) or key-value form. |
| `MAX_EXPIRATION_MINUTES` | `525600` | Maximum expiration time in minutes (default = 1 year) |
| `WRITE_RATE_PER_MIN` | `10` | Rate limit for POST /api/shorten (per IP, per minute) |
| `READ_RATE_PER_MIN` | `120` | Rate limit for GET requests (per IP, per minute) |
| `MAX_BODY_BYTES` | `4096` | Maximum POST body size in bytes (rejects oversize requests with 400) |
| `CLEANUP_INTERVAL_MINS` | `5` | Background cleanup interval for expired URLs (in minutes) |
| `SHUTDOWN_TIMEOUT_SECS` | `10` | Graceful shutdown timeout (in seconds) |
| `TLS_CERT_FILE` | (none) | Path to TLS certificate file (e.g., `/etc/tls/cert.pem`); HTTPS is enabled when both this and `TLS_KEY_FILE` are set |
| `TLS_KEY_FILE` | (none) | Path to TLS private key file (e.g., `/etc/tls/key.pem`) |
| `TRUST_PROXY` | `false` | Trust `X-Forwarded-For` header for rate limiting (set to `true` when behind reverse proxy) |
| `DENY_HOSTS` | (none) | Comma-separated list of hostnames to block as destination URLs. Matches the host and any subdomain (e.g., `evil.com` blocks `a.evil.com`). |
| `DENY_HOSTS_FILE` | (none) | Path to a text file with one host per line. Blank and `#`-prefixed lines are ignored. Merged with `DENY_HOSTS`. |
| `CLICK_LOG_IP` | `false` | When `true`, the click event log stores a salted SHA-256 hash of the client IP. Default off for privacy; turn on for unique-visitor counting. |
| `CLICK_IP_SALT` | (random) | Salt mixed into IP hashes. Empty → fresh random per-process salt (unique counts reset on restart). Set to a long random string for cross-deploy stability. |
| `CLICK_RETENTION_DAYS` | `90` | The SQLite cleanup goroutine prunes click events older than this many days. Set to `0` to disable pruning (events kept forever — only do this on low-volume deployments). The memory backend caps to the most recent 1000 events per code regardless of this setting. |
| `SHUTDOWN_DRAIN_SECS` | `5` | Sleep window between SIGTERM and `server.Shutdown` so load balancers and service-mesh sidecars can finish propagating the deregistration. Set to `0` to skip the drain. |
| `METRICS_TOKEN` | (none) | When set, `GET /metrics` and `GET /api/audit` require `Authorization: Bearer <token>`. Empty (the default) leaves both endpoints open — fine when they're firewalled or only reachable on a private network; set this when scrapers cross an untrusted boundary. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | (none) | When set, traces are exported via OTLP/HTTP to this endpoint (e.g. `http://otel-collector:4318`). Reads all standard `OTEL_*` env vars — `OTEL_SERVICE_NAME`, `OTEL_EXPORTER_OTLP_HEADERS`, etc. Empty (the default) disables the exporter; W3C trace-context propagation still works inbound/outbound so child services see the same trace ID. |

### Example: Production Deployment

```bash
export PORT=443
export BASE_URL=https://short.example.com
export STORAGE_BACKEND=sqlite
export SQLITE_PATH=/var/lib/tiny-url/data.db
export TLS_CERT_FILE=/etc/tls/short.example.com/fullchain.pem
export TLS_KEY_FILE=/etc/tls/short.example.com/privkey.pem
export TRUST_PROXY=true
export MAX_EXPIRATION_MINUTES=262800  # 6 months
export WRITE_RATE_PER_MIN=30
export READ_RATE_PER_MIN=300

./tiny-url
```

### Example: Development with SQLite

```bash
export STORAGE_BACKEND=sqlite
export SQLITE_PATH=./dev.db
export BASE_URL=http://localhost:8080

go run .
```

## Deployment

### Local Development

```bash
go run .
# Server listens on http://localhost:8080
# Data stored in memory (lost on restart)
```

### Docker

A multi-stage [`Dockerfile`](Dockerfile) is included. The runtime image is `gcr.io/distroless/static:nonroot` — no shell, no glibc, no package manager — so the attack surface inside the container is the binary plus the embedded static assets. This works because the SQLite driver (`modernc.org/sqlite`) is pure Go, letting the build emit a fully static binary.

```bash
# Build (~15 MB final image)
docker build -t tiny-url .

# Run (default: memory backend, port 8080)
docker run -p 8080:8080 tiny-url

# Run with persistent SQLite on a named volume
docker run -p 8080:8080 \
  -e STORAGE_BACKEND=sqlite \
  -e SQLITE_PATH=/data/tiny-url.db \
  -v tinyurl-data:/data \
  tiny-url
```

The image runs as `nonroot` (uid 65532) by default. Static assets are embedded into the binary via `go:embed`, so no `COPY static/` step is needed at runtime.

### Reverse Proxy Setup (nginx)

When running behind a reverse proxy, enable `TRUST_PROXY=true` to correctly attribute rate limits to client IPs.

```nginx
upstream tiny_url {
    server localhost:8080;
}

server {
    listen 443 ssl http2;
    server_name short.example.com;

    ssl_certificate /etc/tls/short.example.com/fullchain.pem;
    ssl_certificate_key /etc/tls/short.example.com/privkey.pem;

    location / {
        proxy_pass http://tiny_url;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $host;
    }
}
```

Then run the application with:
```bash
export PORT=8080
export BASE_URL=https://short.example.com
export TRUST_PROXY=true
# TLS termination is handled by nginx — leave TLS_CERT_FILE/TLS_KEY_FILE unset.
./tiny-url
```

### TLS/HTTPS (Direct)

Generate a self-signed certificate for testing:
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

Or use Let's Encrypt with Certbot:
```bash
certbot certonly --standalone -d short.example.com
```

Then run with:
```bash
export PORT=443
export BASE_URL=https://short.example.com
export TLS_CERT_FILE=/path/to/cert.pem
export TLS_KEY_FILE=/path/to/key.pem
./tiny-url
```

The server will enforce HTTPS via the `Strict-Transport-Security` header, and all HTTP connections will need a reverse proxy to redirect to HTTPS.

## Persistence

### Memory Storage (Default)

- **When to use**: Development, ephemeral deployments, CI/CD testing
- **Data lifetime**: Lost on server restart
- **Performance**: Fastest (O(1) in-memory map)
- **Footprint**: Grows linearly with number of URLs
- **No external dependencies**

```bash
export STORAGE_BACKEND=memory
go run .
```

### SQLite Persistence

- **When to use**: Production, data retention across restarts
- **Data lifetime**: Persists across server restarts and upgrades
- **Performance**: Very fast (WAL mode, indexed lookups)
- **Footprint**: Bounded by database file size
- **Single dependency**: `modernc.org/sqlite` (pure Go, no CGO)

```bash
export STORAGE_BACKEND=sqlite
export SQLITE_PATH=/var/lib/tiny-url/urls.db
go run .
```

**Database Schema:**
```sql
CREATE TABLE IF NOT EXISTS urls (
    short_code TEXT PRIMARY KEY,
    original_url TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    click_count INTEGER NOT NULL DEFAULT 0,
    last_accessed INTEGER,
    owner_token_hash BLOB
);
CREATE INDEX IF NOT EXISTS idx_expires_at 
    ON urls(expires_at) WHERE expires_at IS NOT NULL;
```

**Automatic Cleanup:**
- Expired URLs are removed by background routine every 5 minutes (configurable)
- Cleanup is non-blocking (runs in separate goroutine)
- Cleanup is context-aware (stops on graceful shutdown)

## API Reference

### POST /api/shorten

Create a shortened URL with optional custom alias and expiration.

**Required header:**
- `X-Requested-With: XMLHttpRequest` (CSRF defense)

**Request Body:**
```json
{
  "url": "string (required) — must start with http:// or https://",
  "custom_code": "string (optional) — 3-32 alphanumeric/underscore/hyphen",
  "expiration_mins": "integer (optional) — 0 or omitted = no expiration"
}
```

**Response:** 201 Created
```json
{
  "short_code": "string",
  "short_url": "string",
  "original_url": "string",
  "admin_token": "string (base64-encoded 32-byte token for analytics access)",
  "expires_at": "timestamp (optional, omitted if no expiration)"
}
```

**Error Responses:**
- `400 Bad Request` — invalid URL, too long, SSRF blocked, invalid custom code, reserved word, body too large
- `409 Conflict` — custom code already in use
- `429 Too Many Requests` — rate limit exceeded

### GET /{code}

Redirect to the original URL and increment click counter.

**Response:** 
- `302 Found` — redirect with `Location: <original_url>` header
- `404 Not Found` — code doesn't exist
- `410 Gone` — code has expired

**Rate Limiting:** Counts toward READ rate limit (default 120 per minute per IP)

### GET /api/analytics/{code}

Retrieve analytics for a shortened URL (restricted to creator).

**Required header:**
- `Authorization: Bearer <admin_token>` (from POST /api/shorten response)

**Response:** 200 OK
```json
{
  "short_code": "string",
  "original_url": "string",
  "click_count": "integer",
  "created_at": "ISO 8601 timestamp",
  "expires_at": "ISO 8601 timestamp (omitted if no expiration)",
  "last_accessed": "ISO 8601 timestamp (null if never accessed)"
}
```

**Error Responses:**
- `401 Unauthorized` — missing or invalid bearer token
- `404 Not Found` — code doesn't exist
- `410 Gone` — code has expired
- `429 Too Many Requests` — rate limit exceeded

### GET /api/qr/{code}

Generate a PNG QR code encoding the short URL.

**Response:** 200 OK
- Content-Type: `image/png`
- Content-Disposition: `inline; filename="qr-{code}.png"`
- Body: 256×256 PNG image

**Caching:** Cached for 1 hour (`Cache-Control: private, max-age=3600`)

**Error Responses:**
- `404 Not Found` — code doesn't exist
- `410 Gone` — code has expired
- `429 Too Many Requests` — rate limit exceeded

### GET /healthz

Liveness check (no database ping).

**Response:** 200 OK
```json
{
  "status": "ok",
  "storage": "memory|sqlite"
}
```

This endpoint is not rate-limited and is safe for frequent health checks.

## Testing

Run the test suite:
```bash
go test ./...
```

Run with coverage:
```bash
go test -cover ./...
```

Run a specific test:
```bash
go test ./handlers -run TestShortenHandler
```

Test categories:
- **services/validation_test.go**: URL/IP validation, custom code validation
- **services/shortcode_test.go**: Code generation, collision handling
- **services/storage_sqlite_test.go**: CRUD operations, persistence, cleanup
- **handlers/shorten_test.go**: URL shortening, custom codes, SSRF rejection, expiration cap
- **handlers/analytics_test.go**: Bearer token auth, expired URLs
- **handlers/redirect_test.go**: Redirects, click increment, 404/410 responses
- **middleware/ratelimit_test.go**: Per-IP rate limiting, window behavior

## Known Limitations & Trade-offs

1. **TOCTOU in SSRF validation**: URL is validated at creation but could be compromised before redirect. Mitigation: non-routable ranges are globally non-routable anyway.
2. **Single process only**: No distributed cache or load balancing. Scale with reverse proxy and multiple instances with SQLite (requires careful WAL setup for concurrent writes).
3. **Analytics not anonymous**: Creator can be identified by whoever holds the admin token. Accept as feature (not a bug) for security-conscious users who want private analytics.
4. **Custom code collision**: TOCTOU race between Exists() check and Set(). Mitigation: SQLite's UNIQUE constraint on short_code provides second line of defense; in practice extremely rare due to low collision probability.
5. **Memory backend unbounded growth**: If expiration_mins is large and cleanup interval is long, in-memory storage can grow unchecked. Mitigation: use SQLite for production with configurable cleanup interval.

## Future Enhancements

- User accounts and API keys for batch operations
- Dashboard showing all URLs created by a user
- URL preview and safety checking (Safe Browsing API integration)
- Custom redirect interstitial page
- Export analytics to CSV
- Webhook notifications on click
- URL grouping/collections
- Batch URL shortening
- Rate limiting per API key (instead of per IP)
- Multi-region deployment with replication

## Built With

- **Go 1.22+** — standard library only for core functionality
- **modernc.org/sqlite** (v1.50.0) — pure Go SQLite driver for optional persistence
- **github.com/skip2/go-qrcode** (v0.0.0-20200617195104-da1b6568686e) — QR code generation
- **Vanilla JavaScript** — no frontend frameworks

## License

This project is open source and available for personal and commercial use.

## Contributing

Contributions welcome! Areas for contribution:
- Additional test coverage
- Performance optimizations
- Deployment documentation
- UI/UX improvements
- Localization

## Author

Created with Claude Code
