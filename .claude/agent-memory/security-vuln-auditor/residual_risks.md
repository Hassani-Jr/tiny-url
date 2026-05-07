---
name: Known Residual Risks
description: Confirmed residual threat surface after hardening rounds — areas worth monitoring or investing in next
type: project
---

1. **DNS TOCTOU (SSRF residual):** Validation resolves DNS once at shorten time (services/validation.go:89). An attacker with DNS control can pass validation with a public IP then switch the record to 169.254.169.254 before the redirect fires. Acknowledged in code comment at validation.go:47-51. Mitigation would require dial-time IP pinning or resolver lock.

2. **localStorage token exposure:** Owner tokens stored in localStorage (static/app.js:101). XSS on same origin — even from a third-party script in a future dependency — reads all tinyurl:token:* keys. Current CSP (script-src 'self') limits this if assets are not compromised.

3. **Proxy trust model:** TRUST_PROXY=true reads rightmost XFF; no explicit allow-list of trusted proxy CIDR. Multi-hop topologies can let attackers control the rightmost IP. Documented in ratelimit.go:104-107.

4. **/metrics unauthenticated:** GET /metrics (expvar) is outside rate limiter, publicly accessible. Leaks request counts per route and any expvar added in future. Low risk today; grows with observability additions.

5. **Short-code enumeration:** Default 6-char alphanumeric code space is ~2.2B but codes are short enough that a persistent scraper enumerating sequentially could map the corpus. Analytics/click-data is owner-token-gated so exposure is limited to existence + original URL.

6. **No global admin / operator API:** There is no management plane to bulk-revoke URLs, rotate secrets, or inspect all mappings without direct DB access. Operator recourse to abuse is manual SQLite edits.

7. **CLICK_IP_SALT not set warning:** If CLICK_IP_SALT is empty, a random per-process salt is used and a Warn is logged. Unique-visitor counts reset on restart. Operators who ignore the warning lose cross-restart visitor identity.

**Why:** Captured during threat model review 2026-05-05.
**How to apply:** When reviewing future PRs, check whether these residual risks are being addressed or inadvertently widened.
