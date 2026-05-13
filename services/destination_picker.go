package services

import (
	"math/rand/v2"
	"tiny-url/models"
)

// PickDestination returns one entry from the pool, chosen proportionally
// to weight. Caller-supplied randomness keeps the function testable:
// pass nil for the per-process default RNG, or a seeded *rand.Rand for
// deterministic tests.
//
// Returns nil when the pool is empty so the caller can fall back to
// OriginalURL without a special-case check. Validation upstream
// (ValidateDestinations) guarantees weights are >= 1, so we don't
// guard against the zero-total-weight pathology here.
func PickDestination(pool []models.Destination, rng *rand.Rand) *models.Destination {
	if len(pool) == 0 {
		return nil
	}
	if len(pool) == 1 {
		return &pool[0]
	}
	total := 0
	for _, d := range pool {
		total += d.Weight
	}
	var r int
	if rng != nil {
		r = rng.IntN(total)
	} else {
		r = rand.IntN(total)
	}
	cum := 0
	for i := range pool {
		cum += pool[i].Weight
		if r < cum {
			return &pool[i]
		}
	}
	// Fallthrough guard for float / int rounding edge cases — the
	// loop above should always return, but a final-element fallback
	// keeps the function panic-free in the face of a future refactor.
	return &pool[len(pool)-1]
}
