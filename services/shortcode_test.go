package services

import (
	"regexp"
	"testing"
	"time"

	"tiny-url/models"
)

func TestGenerateShortCode(t *testing.T) {
	store := NewMemoryStore()

	t.Run("generates valid format", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			code, err := GenerateShortCode(store)
			if err != nil {
				t.Fatalf("GenerateShortCode() error = %v", err)
			}

			// Check length
			if len(code) != 6 {
				t.Errorf("GenerateShortCode() length = %d, want 6", len(code))
			}

			// Check character set (Base62: 0-9, a-z, A-Z)
			if !regexp.MustCompile(`^[0-9a-zA-Z]{6}$`).MatchString(code) {
				t.Errorf("GenerateShortCode() code = %q, does not match Base62 pattern", code)
			}
		}
	})

	t.Run("generates unique codes", func(t *testing.T) {
		store := NewMemoryStore()
		codes := make(map[string]bool)

		for i := 0; i < 1000; i++ {
			code, err := GenerateShortCode(store)
			if err != nil {
				t.Fatalf("GenerateShortCode() error = %v", err)
			}

			if codes[code] {
				t.Errorf("GenerateShortCode() generated duplicate: %q", code)
			}
			codes[code] = true

			// Add to store so next code knows it's taken
			store.Set(code, &models.URLMapping{
				ID:          code,
				OriginalURL: "https://example.com",
				CreatedAt:   time.Now(),
			})
		}

		if len(codes) != 1000 {
			t.Errorf("GenerateShortCode() generated %d unique codes, want 1000", len(codes))
		}
	})

	t.Run("collision retry works", func(t *testing.T) {
		store := NewMemoryStore()

		// Seed store with a code
		existingCode := "aaaaaa"
		store.Set(existingCode, &models.URLMapping{
			ID:          existingCode,
			OriginalURL: "https://example.com",
			CreatedAt:   time.Now(),
		})

		// GenerateShortCode should retry and find a different code
		code, err := GenerateShortCode(store)
		if err != nil {
			t.Fatalf("GenerateShortCode() error = %v", err)
		}

		if code == existingCode {
			t.Errorf("GenerateShortCode() returned existing code %q", code)
		}
	})
}

// Benchmark code generation
func BenchmarkGenerateShortCode(b *testing.B) {
	store := NewMemoryStore()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GenerateShortCode(store)
	}
}
