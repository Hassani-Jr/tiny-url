# Security Policy

## Reporting a Vulnerability

If you find a security issue in tiny-url, please report it privately to
**whass004@fiu.edu** rather than filing a public GitHub issue.

Useful information in a report:

- A clear description of the vulnerability
- Reproduction steps or a proof-of-concept
- Affected version (commit SHA from `tiny-url --version`)
- The deployment context if relevant (memory backend vs. SQLite, behind a
  proxy with `TRUST_PROXY`, etc.)

You can expect an initial acknowledgement within a few days. There is no
formal SLA — this is a personal project — but I'll work with you on a fix
and on coordinated disclosure.

## Threat Model Summary

This is a single-binary URL shortener intended for personal or small-team
use. The trust boundaries and the controls protecting them are:

| Boundary | Threats mitigated | Where |
|---|---|---|
| Internet → Go process | SSRF (private/loopback IPs, DNS rebinding), CSRF, rate-limit abuse, oversized bodies | `services.ValidateDestinationURL`, `services.ValidateHostAtRuntime`, `middleware.RequireXRequestedWith`, `middleware.NewLimiter`, `http.MaxBytesReader` |
| Untrusted destination URL | Phishing/abuse via shortened links | `services.DenyList` (creation + redirect re-check) |
| Untrusted client → owner data | Reading or modifying URLs you don't own | 32-byte CSPRNG admin tokens, SHA-256 stored, `subtle.ConstantTimeCompare` |
| Browser → stored token | XSS, hostile extension reading `localStorage` | CSP `script-src 'self'`; **documented residual risk** (see below) |
| OS / filesystem | Process crash, panic, panic stack leakage | `middleware.Recover`, structured logs through `slog` |

## Known Limitations

These are deliberate trade-offs, not bugs:

### Owner tokens live in browser localStorage

The web UI stashes admin tokens in `localStorage` keyed by short code so
analytics / edit / delete keep working across page loads. This is readable
by **any same-origin JavaScript** and by **browser extensions with broad
host permissions**.

Mitigations in place:
- CSP `script-src 'self'` blocks injected external scripts.
- Frontend uses `textContent` and `createElement` (not `innerHTML`) when
  rendering server data.

If your threat model includes either future XSS or hostile extensions,
**use the REST API directly** and store the token in a dedicated secret
manager — don't rely on the web UI. The plaintext token is shown once in
the `POST /api/shorten` response; save it deliberately at that point.

### DNS rebinding is bounded, not eliminated

The redirect handler re-resolves the destination host on every click and
re-runs the SSRF guard, so a host that flips DNS to a private/loopback IP
is blocked the moment the cached resolution expires (TTL: 5 seconds in
the in-process DNS cache, or whatever your OS resolver caches first). A
narrow window remains where a click immediately following a rebind hits
the still-cached good resolution. Acceptable for the threat model; not
acceptable for a service that needs sub-second guarantees.

### The deny-list reloads at startup only

`DENY_HOSTS` and `DENY_HOSTS_FILE` are read once. The redirect path
re-checks the in-memory list on every redirect, so adding a host to the
deny-list takes effect for new redirects after a restart, not for new
shortenings created before the restart. For dynamic feed updates you'd
want a SIGHUP-triggered reload (not currently implemented).

### `/metrics` is open by default

`expvar`-style metrics are unauthenticated unless `METRICS_TOKEN` is set.
Operators are expected to firewall the endpoint or set a token if
exposing it to an untrusted network.

### Single-process only

Rate limiting is per-process. The click-event SSE pub-sub is in-process.
Running multiple replicas behind a load balancer means rate limits apply
per-replica and SSE clients miss events served by other replicas. For a
true multi-replica deployment you'd need Redis (rate-limit) and an event
bus (SSE).

## What's Considered Adequate

These have been audited and are not currently a concern:

- **SQL injection**: parameterized queries throughout `services/storage_sqlite.go`.
- **XSS via API responses**: all responses are JSON; the dashboard never
  `innerHTML`-interpolates server data.
- **Clickjacking**: `X-Frame-Options: DENY` plus CSP `frame-ancestors 'none'`.
- **Click-counter drift**: `RecordClick` is atomic in both stores.
- **Panic recovery**: `middleware.Recover` catches handler panics, logs
  them via slog with the request ID, and returns 500.
- **Short-code collision**: `Set` + `INSERT OR IGNORE` closes the
  Exists/Set TOCTOU race; collisions surface as 409.

## Vulnerability Severity

Roughly Apache-style:

- **Critical** — remote unauthenticated RCE, full data exfiltration, auth bypass
- **High** — SSRF reaching previously-blocked targets, owner-token compromise without prior access, persistent XSS
- **Medium** — non-persistent XSS, DoS without authentication, info disclosure
  bounded to the affected URL
- **Low** — operational issues with limited blast radius (e.g., log flooding)

## Out of Scope

- Findings that depend on operator misconfiguration explicitly documented
  as supported (e.g., running without TLS in production — see README).
- Findings that require an attacker who already controls the operator's
  filesystem or OS account.
- Reports about features the threat model deliberately excludes
  (multi-tenant accounts, OAuth, geo-blocking, etc.).
