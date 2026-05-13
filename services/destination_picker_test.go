package services

import (
	"math/rand/v2"
	"testing"
	"tiny-url/models"
)

// TestPickDestinationEmptyAndSingle covers the trivial cases. Empty
// pool returns nil (caller falls back to OriginalURL); single entry
// always wins.
func TestPickDestinationEmptyAndSingle(t *testing.T) {
	if PickDestination(nil, nil) != nil {
		t.Errorf("PickDestination(nil) = non-nil, want nil")
	}
	if PickDestination([]models.Destination{}, nil) != nil {
		t.Errorf("PickDestination([]) = non-nil, want nil")
	}
	one := []models.Destination{{URL: "https://a.example", Weight: 5}}
	got := PickDestination(one, nil)
	if got == nil || got.URL != "https://a.example" {
		t.Errorf("PickDestination([1]) = %+v, want a.example", got)
	}
}

// TestPickDestinationDistribution verifies that with a 9:1 weighting,
// running the picker many times produces a roughly 90/10 split. Uses
// a seeded RNG so the test is deterministic — the test runs PCG with
// a fixed seed and asserts the count falls in a generous band so the
// test isn't flaky against statistical noise.
func TestPickDestinationDistribution(t *testing.T) {
	pool := []models.Destination{
		{URL: "https://a", Weight: 9},
		{URL: "https://b", Weight: 1},
	}
	rng := rand.New(rand.NewPCG(42, 24))
	const n = 10000
	counts := map[string]int{}
	for i := 0; i < n; i++ {
		d := PickDestination(pool, rng)
		counts[d.URL]++
	}
	// 9/10 = 9000 expected for "a". Allow ±300 (≈ 3%) slack — far
	// outside random walk for n=10000 but tight enough to catch a
	// real distribution bug (a 50/50 picker would land in the
	// ~5000 range and fail this assertion immediately).
	if counts["https://a"] < 8700 || counts["https://a"] > 9300 {
		t.Errorf("weight-9 destination got %d/%d hits, want ~9000±300", counts["https://a"], n)
	}
	if counts["https://b"] < 700 || counts["https://b"] > 1300 {
		t.Errorf("weight-1 destination got %d/%d hits, want ~1000±300", counts["https://b"], n)
	}
}

// TestPickDestinationCoversAllEntries: every non-zero-weight entry
// must be reachable. Equal weights → each one fires roughly 1/N of
// the time; we just check each appears at least once across many
// iterations.
func TestPickDestinationCoversAllEntries(t *testing.T) {
	pool := []models.Destination{
		{URL: "u1", Weight: 1},
		{URL: "u2", Weight: 1},
		{URL: "u3", Weight: 1},
	}
	rng := rand.New(rand.NewPCG(1, 2))
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		seen[PickDestination(pool, rng).URL] = true
	}
	for _, want := range []string{"u1", "u2", "u3"} {
		if !seen[want] {
			t.Errorf("destination %q never fired across 1000 picks — picker missed an entry", want)
		}
	}
}
