package handlers

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"

	"go.opentelemetry.io/otel"
)

// passwordTracer scopes spans created by the password-verify path.
// Resolved once at package init; the global TracerProvider is a no-op
// when tracing isn't configured so this is free off the hot path.
var passwordTracer = otel.Tracer("tiny-url/password")

// passwordIterations is the PBKDF2 iteration count used to derive a key
// from a user-supplied short-URL passphrase. 200_000 with SHA-256 is in the
// OWASP 2023 recommended range; on a modern x86_64 core that's ~50ms per
// hash. The redirect path is already per-IP rate-limited, so a multi-
// hundred-millisecond hash is acceptable interactively and would be
// painful for an offline attacker who exfiltrated the rows.
const passwordIterations = 200_000

// passwordKeyLen and passwordSaltLen are sized to match SHA-256's output
// (32 bytes) and a generous random salt (16 bytes). Both numbers are
// arbitrary as long as they're consistent across hash + verify.
const (
	passwordKeyLen  = 32
	passwordSaltLen = 16
)

// hashPassword derives a PBKDF2-SHA256 key from password with a fresh
// random salt. Returns (hash, salt, err). The caller stores both alongside
// the URL row; verifyPassword recomputes the hash on each redirect.
//
// The password length is capped at 256 bytes upstream by the body-size
// limit on POST /api/shorten + PATCH /api/url/{code}, so there's no
// per-call short-circuit needed here.
func hashPassword(password string) ([]byte, []byte, error) {
	salt := make([]byte, passwordSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, passwordIterations, passwordKeyLen)
	if err != nil {
		return nil, nil, err
	}
	return key, salt, nil
}

// verifyPassword reports whether password derives the stored hash when run
// through PBKDF2-SHA256 with the stored salt. Constant-time comparison
// prevents timing oracles even though the per-hash cost (~50ms) already
// largely drowns out the per-byte compare difference.
//
// Wrapped in a trace span so operators can see when the redirect path
// is being slowed by failed-password attempts — the ~50 ms PBKDF2 cost
// is the dominant per-redirect work when this path fires, so making
// it observable is worth the no-op span overhead.
func verifyPassword(ctx context.Context, password string, hash, salt []byte) bool {
	_, span := passwordTracer.Start(ctx, "password.verify")
	defer span.End()
	if len(hash) == 0 || len(salt) == 0 {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, passwordIterations, passwordKeyLen)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, hash) == 1
}
