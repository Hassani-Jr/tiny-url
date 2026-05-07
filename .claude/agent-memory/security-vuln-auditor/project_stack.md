---
name: Project Stack & Architecture
description: Language, framework, storage, middleware chain, and confirmed security controls for tiny-url Go service
type: project
---

Go 1.25 URL shortener; standard library net/http mux (1.22+ method+path routing). Two storage backends: MemoryStore and SQLiteStore (modernc.org/sqlite, WAL, foreign keys ON, cascading deletes). Static assets embedded via embed.FS.

**Middleware chain (outer→inner):** RequestID → Logger → Metrics → Recover → SecurityHeaders → rate limiter → handlers

**Confirmed controls:**
- SSRF: ValidateDestinationURL in services/validation.go does DNS resolution + categorizeIP (loopback/private/link-local/multicast/CGNAT/unspecified). Deny-list re-checked at redirect time (handlers/redirect.go:65).
- Rate limiting: per-IP fixed-window, separate write (default 10/min) and read (default 120/min) limiters. ClientIP reads rightmost XFF entry when TRUST_PROXY=true.
- Owner tokens: 32-byte crypto/rand, base64url encoded, SHA-256 stored; constant-time compare in handlers/auth.go.
- CSRF: RequireXRequestedWith on POST /api/shorten; bearer token is CSRF defence on PATCH/DELETE.
- Security headers: CSP default-src 'self', X-Frame-Options DENY, X-Content-Type-Options nosniff, Referrer-Policy no-referrer, HSTS when TLS.
- Click privacy: raw UA never stored; coarse 5-class UA bucket; Referer truncated to 512 chars; IP hashed with salted SHA-256 (opt-in).
- Body size: MaxBytesReader(4096 default) on POST/PATCH.
- No sessions or cookies — stateless bearer token model.
- SQLite: parameterized queries throughout; no string interpolation.

**Why:** Threat model document produced 2026-05-05.
**How to apply:** Use this as baseline when auditing incremental changes — don't re-flag confirmed controls.
