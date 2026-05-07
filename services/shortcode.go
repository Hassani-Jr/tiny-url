package services

import (
	"crypto/rand"
	"errors"
)

const (
	shortCodeLength = 6
	base62Chars     = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	maxRetries      = 5
	// base62RejectThreshold is the largest multiple of len(base62Chars) that
	// fits in a byte (256 - 256%62 = 248). Random bytes at or above this
	// value are discarded so each base62 character is uniformly distributed —
	// a plain `b % 62` would make the first 8 chars ~1.6% more likely.
	base62RejectThreshold = 256 - (256 % 62)
)

// GenerateShortCode generates a random base62-encoded short code
// It checks for collisions against the provided storage and retries if needed
func GenerateShortCode(storage Store) (string, error) {
	for range maxRetries {
		code, err := generateRandomBase62(shortCodeLength)
		if err != nil {
			return "", err
		}

		// Check for collision
		if !storage.Exists(code) {
			return code, nil
		}
	}

	return "", errors.New("failed to generate unique short code after maximum retries")
}

// generateRandomBase62 creates a random base62 string of the specified length.
// Uses rejection sampling against base62RejectThreshold so each output
// character is drawn from a uniform distribution — see the threshold
// definition for the bias being avoided.
func generateRandomBase62(length int) (string, error) {
	code := make([]byte, length)
	buf := make([]byte, length)
	pos := 0
	for pos < length {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if b >= base62RejectThreshold {
				continue
			}
			code[pos] = base62Chars[b%byte(len(base62Chars))]
			pos++
			if pos == length {
				break
			}
		}
	}
	return string(code), nil
}
