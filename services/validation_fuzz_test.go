package services

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

// FuzzValidateDestinationURL feeds random strings through the URL validator
// and asserts two things:
//
//  1. The function never panics regardless of input.
//  2. Any input that returns nil (i.e. "valid") really IS valid by the
//     simple, declarative criteria the validator promises: scheme is
//     http or https, no embedded credentials, and the host parses.
//
// This is exactly the kind of pure input parser where edge cases hide
// (RFC 3986 weird-but-legal URLs, unicode, percent-encoding tricks). Run
// with `go test -fuzz=FuzzValidateDestinationURL -fuzztime=60s ./services/`.
func FuzzValidateDestinationURL(f *testing.F) {
	for _, seed := range []string{
		"https://example.com",
		"http://1.1.1.1",
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"",
		"://broken",
		"http://user:pass@1.1.1.1",
		"https://[::1]",
		"https://1.1.1.1:99999",
		"https://" + strings.Repeat("a", 3000) + ".com",
		"file:///etc/passwd",
		"ftp://example.com",
		"https://exa%6dple.com",
		"https://localhost",
		"http://127.0.0.1",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		// Property 1: never panics.
		err := ValidateDestinationURL(raw, nil)
		if err != nil {
			return
		}
		// Property 2: a "valid" return must satisfy the declared rules.
		// Re-parse and re-check to catch any drift between the validator
		// and its own contract.
		u, perr := url.Parse(raw)
		if perr != nil {
			t.Fatalf("validator accepted unparseable URL %q (parse err: %v)", raw, perr)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			t.Fatalf("validator accepted non-http(s) scheme %q in %q", u.Scheme, raw)
		}
		if u.User != nil {
			t.Fatalf("validator accepted credentials in %q", raw)
		}
		if u.Hostname() == "" {
			t.Fatalf("validator accepted empty host in %q", raw)
		}
		if len(raw) > MaxURLLength {
			t.Fatalf("validator accepted oversized URL (len=%d > %d) %q", len(raw), MaxURLLength, raw)
		}
		// And: a "valid" host must not be one we know is private.
		host := strings.ToLower(u.Hostname())
		if host == "localhost" || strings.HasSuffix(host, ".localhost") {
			t.Fatalf("validator accepted loopback hostname in %q", raw)
		}
	})
}

// FuzzValidateCustomCode checks the simpler regex-driven validator for
// drift between the regex, the reserved-words set, and the documented
// contract.
func FuzzValidateCustomCode(f *testing.F) {
	for _, seed := range []string{
		"abc",
		"abc-123",
		"my_link",
		"a", // too short
		"",
		strings.Repeat("a", 33), // too long
		"api",                   // reserved
		"API",                   // reserved (case-insensitive)
		"with space",
		"unicode-é",
		"slash/in/code",
		strings.Repeat("a", 32), // exact-max
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, code string) {
		// Property 1: never panics.
		err := ValidateCustomCode(code)
		if err == nil {
			// Property 2: an accepted code must be 3-32 chars of [A-Za-z0-9_-]
			// AND not in the reserved set.
			if len(code) < 3 || len(code) > 32 {
				t.Fatalf("accepted code %q has length %d (must be 3-32)", code, len(code))
			}
			for _, r := range code {
				if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
					t.Fatalf("accepted code %q contains disallowed rune %q", code, r)
				}
			}
			if reservedCodes[strings.ToLower(code)] {
				t.Fatalf("accepted code %q is in the reserved set", code)
			}
			return
		}
		// Property 3: rejection must be one of the documented reasons.
		if !errors.Is(err, ErrInvalidCustomCode) && !errors.Is(err, ErrReservedCode) {
			t.Fatalf("unexpected error type for %q: %v", code, err)
		}
	})
}
