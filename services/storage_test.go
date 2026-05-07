package services

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"tiny-url/models"
)

// runStoreContractTests exercises the parts of the Store contract that are
// new or shared across backends: Delete and Ping. Per-backend specifics
// (TTL semantics, conflict shapes) are covered in their dedicated suites.
func runStoreContractTests(t *testing.T, newStore func(t *testing.T) Store) {
	t.Helper()

	t.Run("delete existing", func(t *testing.T) {
		s := newStore(t)
		_ = s.Set("victim", &models.URLMapping{
			ID: "victim", OriginalURL: "https://example.com", CreatedAt: time.Now(),
		})
		if err := s.Delete("victim"); err != nil {
			t.Fatalf("Delete() error = %v", err)
		}
		if s.Exists("victim") {
			t.Errorf("mapping still exists after Delete")
		}
	})

	t.Run("delete missing returns ErrNotFound", func(t *testing.T) {
		s := newStore(t)
		err := s.Delete("nope")
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("Delete(missing) error = %v, want ErrNotFound", err)
		}
	})

	t.Run("ping ok", func(t *testing.T) {
		s := newStore(t)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := s.Ping(ctx); err != nil {
			t.Errorf("Ping() error = %v", err)
		}
	})

	t.Run("record click and read events", func(t *testing.T) {
		s := newStore(t)
		_ = s.Set("ev", &models.URLMapping{
			ID: "ev", OriginalURL: "https://example.com", CreatedAt: time.Now(),
		})
		// Three events with distinct timestamps
		base := time.Now()
		for i := 0; i < 3; i++ {
			err := s.RecordClick("ev", models.ClickEvent{
				At:      base.Add(time.Duration(i) * time.Second),
				UAClass: "desktop",
				Referer: "https://ref.example/",
			})
			if err != nil {
				t.Fatalf("RecordClick: %v", err)
			}
		}
		got, err := s.RecentClicks("ev", 0)
		if err != nil {
			t.Fatalf("RecentClicks: %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("got %d events, want 3", len(got))
		}
		// Newest first
		if !got[0].At.After(got[2].At) {
			t.Errorf("events not ordered newest-first: %+v", got)
		}
		// Atomic guarantee: click_count must equal len(events).
		m, err := s.Get("ev")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if m.ClickCount != int64(len(got)) {
			t.Errorf("click_count=%d, len(events)=%d — RecordClick must keep them in sync",
				m.ClickCount, len(got))
		}
	})

	t.Run("record click on missing code", func(t *testing.T) {
		s := newStore(t)
		err := s.RecordClick("nope", models.ClickEvent{At: time.Now()})
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("RecordClick(missing) = %v, want ErrNotFound", err)
		}
	})

	t.Run("update url and clear expiration", func(t *testing.T) {
		s := newStore(t)
		exp := time.Now().Add(time.Hour)
		_ = s.Set("upd", &models.URLMapping{
			ID: "upd", OriginalURL: "https://old.example", CreatedAt: time.Now(), ExpiresAt: &exp,
		})
		if err := s.Update("upd", "https://new.example", nil, true); err != nil {
			t.Fatalf("Update: %v", err)
		}
		m, err := s.Get("upd")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if m.OriginalURL != "https://new.example" {
			t.Errorf("OriginalURL = %q, want https://new.example", m.OriginalURL)
		}
		if m.ExpiresAt != nil {
			t.Errorf("ExpiresAt = %v, want nil after clearExpiration", m.ExpiresAt)
		}
	})

	t.Run("update missing returns ErrNotFound", func(t *testing.T) {
		s := newStore(t)
		err := s.Update("nope", "https://x.example", nil, false)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("Update(missing) = %v, want ErrNotFound", err)
		}
	})
}

func TestMemoryStoreContract(t *testing.T) {
	runStoreContractTests(t, func(t *testing.T) Store { return NewMemoryStore() })
}

func TestSQLiteStoreContract(t *testing.T) {
	runStoreContractTests(t, func(t *testing.T) Store {
		s, err := NewSQLiteStore(filepath.Join(t.TempDir(), "contract.db"))
		if err != nil {
			t.Fatalf("NewSQLiteStore: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	})
}
