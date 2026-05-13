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
		newURL := "https://new.example"
		if err := s.Update("upd", UpdateFields{OriginalURL: &newURL, ClearExpiration: true}); err != nil {
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
		nope := "https://x.example"
		err := s.Update("nope", UpdateFields{OriginalURL: &nope})
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("Update(missing) = %v, want ErrNotFound", err)
		}
	})

	t.Run("tags round-trip on Set", func(t *testing.T) {
		s := newStore(t)
		_ = s.Set("tg", &models.URLMapping{
			ID: "tg", OriginalURL: "https://example.com", CreatedAt: time.Now(),
			Tags: []string{"work", "urgent"},
		})
		m, err := s.Get("tg")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if len(m.Tags) != 2 || m.Tags[0] != "work" || m.Tags[1] != "urgent" {
			t.Errorf("Tags = %v, want [work urgent]", m.Tags)
		}
	})

	t.Run("tags can be replaced and cleared via Update", func(t *testing.T) {
		s := newStore(t)
		_ = s.Set("tg2", &models.URLMapping{
			ID: "tg2", OriginalURL: "https://example.com", CreatedAt: time.Now(),
			Tags: []string{"a", "b"},
		})
		// Replace
		newTags := []string{"c"}
		if err := s.Update("tg2", UpdateFields{Tags: &newTags}); err != nil {
			t.Fatalf("Update: %v", err)
		}
		m, _ := s.Get("tg2")
		if len(m.Tags) != 1 || m.Tags[0] != "c" {
			t.Errorf("after replace Tags = %v, want [c]", m.Tags)
		}
		// Clear with empty slice
		empty := []string{}
		if err := s.Update("tg2", UpdateFields{Tags: &empty}); err != nil {
			t.Fatalf("Update clear: %v", err)
		}
		m, _ = s.Get("tg2")
		if len(m.Tags) != 0 {
			t.Errorf("after clear Tags = %v, want empty", m.Tags)
		}
	})

	t.Run("max_clicks round-trip and clear", func(t *testing.T) {
		s := newStore(t)
		_ = s.Set("mc", &models.URLMapping{
			ID: "mc", OriginalURL: "https://example.com", CreatedAt: time.Now(),
			MaxClicks: 5,
		})
		m, _ := s.Get("mc")
		if m.MaxClicks != 5 {
			t.Errorf("MaxClicks = %d, want 5", m.MaxClicks)
		}
		zero := int64(0)
		if err := s.Update("mc", UpdateFields{MaxClicks: &zero}); err != nil {
			t.Fatalf("Update clear: %v", err)
		}
		m, _ = s.Get("mc")
		if m.MaxClicks != 0 {
			t.Errorf("MaxClicks after clear = %d, want 0", m.MaxClicks)
		}
	})

	t.Run("password fields round-trip and clear", func(t *testing.T) {
		s := newStore(t)
		hash := []byte{0x01, 0x02, 0x03, 0x04}
		salt := []byte{0x10, 0x20, 0x30, 0x40}
		_ = s.Set("pw", &models.URLMapping{
			ID: "pw", OriginalURL: "https://example.com", CreatedAt: time.Now(),
			PasswordHash: hash, PasswordSalt: salt,
		})
		m, _ := s.Get("pw")
		if !bytesEqual(m.PasswordHash, hash) || !bytesEqual(m.PasswordSalt, salt) {
			t.Errorf("password round-trip failed: hash=%x salt=%x", m.PasswordHash, m.PasswordSalt)
		}
		if err := s.Update("pw", UpdateFields{ClearPassword: true}); err != nil {
			t.Fatalf("Update clear: %v", err)
		}
		m, _ = s.Get("pw")
		if len(m.PasswordHash) != 0 || len(m.PasswordSalt) != 0 {
			t.Errorf("after clear hash=%x salt=%x, want empty", m.PasswordHash, m.PasswordSalt)
		}
	})

	t.Run("clicks_by_bucket aggregates per bucket", func(t *testing.T) {
		s := newStore(t)
		_ = s.Set("bk", &models.URLMapping{
			ID: "bk", OriginalURL: "https://example.com", CreatedAt: time.Now(),
		})
		// 5 events spread across 3 buckets of 1 minute each.
		end := time.Now().Truncate(time.Minute).Add(time.Minute)
		windowStart := end.Add(-3 * time.Minute)
		events := []time.Time{
			windowStart.Add(10 * time.Second),  // bucket 0
			windowStart.Add(30 * time.Second),  // bucket 0
			windowStart.Add(70 * time.Second),  // bucket 1
			windowStart.Add(150 * time.Second), // bucket 2
			windowStart.Add(170 * time.Second), // bucket 2
		}
		for _, ts := range events {
			if err := s.RecordClick("bk", models.ClickEvent{At: ts}); err != nil {
				t.Fatalf("RecordClick: %v", err)
			}
		}
		counts, err := s.ClicksByBucket("bk", end, time.Minute, 3)
		if err != nil {
			t.Fatalf("ClicksByBucket: %v", err)
		}
		want := []int64{2, 1, 2}
		if len(counts) != len(want) {
			t.Fatalf("counts len = %d, want %d", len(counts), len(want))
		}
		for i := range want {
			if counts[i] != want[i] {
				t.Errorf("bucket %d = %d, want %d (full=%v)", i, counts[i], want[i], counts)
			}
		}
	})

	t.Run("clicks_by_bucket on missing code", func(t *testing.T) {
		s := newStore(t)
		_, err := s.ClicksByBucket("nope", time.Now(), time.Hour, 1)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("ClicksByBucket(missing) = %v, want ErrNotFound", err)
		}
	})

	t.Run("api key create + lookup + delete", func(t *testing.T) {
		s := newStore(t)
		hash := []byte("hash-32-bytes-padding-to-thirty2!")[:32]
		k, err := s.CreateAPIKey("laptop", hash)
		if err != nil {
			t.Fatalf("CreateAPIKey: %v", err)
		}
		if k.ID == 0 {
			t.Errorf("CreateAPIKey returned ID=0")
		}
		got, err := s.LookupAPIKey(hash)
		if err != nil {
			t.Fatalf("LookupAPIKey: %v", err)
		}
		if got.ID != k.ID {
			t.Errorf("LookupAPIKey ID = %d, want %d", got.ID, k.ID)
		}
		if got.LastUsedAt == nil {
			t.Errorf("LookupAPIKey did not stamp LastUsedAt")
		}
		// Bind a URL and confirm DeleteAPIKey clears its api_key_id.
		_ = s.Set("u1", &models.URLMapping{
			ID: "u1", OriginalURL: "https://example.com", CreatedAt: time.Now(),
			APIKeyID: k.ID,
		})
		if err := s.DeleteAPIKey(k.ID); err != nil {
			t.Fatalf("DeleteAPIKey: %v", err)
		}
		if _, err := s.LookupAPIKey(hash); !errors.Is(err, ErrNotFound) {
			t.Errorf("LookupAPIKey after delete = %v, want ErrNotFound", err)
		}
		m, err := s.Get("u1")
		if err != nil {
			t.Fatalf("Get after key delete: %v", err)
		}
		if m.APIKeyID != 0 {
			t.Errorf("URL.APIKeyID = %d after key delete, want 0", m.APIKeyID)
		}
	})

	t.Run("list urls by api key returns only owned", func(t *testing.T) {
		s := newStore(t)
		k1, _ := s.CreateAPIKey("k1", []byte("a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a1"))
		k2, _ := s.CreateAPIKey("k2", []byte("b-b-b-b-b-b-b-b-b-b-b-b-b-b-b-b2"))
		_ = s.Set("by-k1", &models.URLMapping{
			ID: "by-k1", OriginalURL: "https://x", CreatedAt: time.Now(),
			APIKeyID: k1.ID,
		})
		_ = s.Set("by-k2", &models.URLMapping{
			ID: "by-k2", OriginalURL: "https://y", CreatedAt: time.Now(),
			APIKeyID: k2.ID,
		})
		_ = s.Set("orphan", &models.URLMapping{
			ID: "orphan", OriginalURL: "https://z", CreatedAt: time.Now(),
		})
		got, err := s.ListURLsByAPIKey(k1.ID, 10, 0)
		if err != nil {
			t.Fatalf("ListURLsByAPIKey: %v", err)
		}
		if len(got) != 1 || got[0].ID != "by-k1" {
			t.Errorf("ListURLsByAPIKey(k1) = %+v, want exactly [by-k1]", got)
		}
	})

	t.Run("audit log records and reads back", func(t *testing.T) {
		s := newStore(t)
		// Log three events out of order; the read MUST return them
		// newest-first regardless of insertion order.
		base := time.Now()
		for i := 0; i < 3; i++ {
			err := s.LogAudit(models.AuditEvent{
				At:         base.Add(time.Duration(i) * time.Second),
				ActorKind:  models.AuditActorAPIKey,
				ActorID:    "42",
				Action:     models.AuditActionURLCreate,
				TargetKind: "url",
				TargetID:   "code-" + string(rune('a'+i)),
				RequestID:  "rid-test",
			})
			if err != nil {
				t.Fatalf("LogAudit %d: %v", i, err)
			}
		}
		got, err := s.RecentAuditEvents(10, 0)
		if err != nil {
			t.Fatalf("RecentAuditEvents: %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("got %d events, want 3", len(got))
		}
		// Newest first: index 0 should be the LAST one inserted.
		if !got[0].At.After(got[2].At) {
			t.Errorf("events not ordered newest-first: %+v", got)
		}
		if got[0].ActorKind != models.AuditActorAPIKey || got[0].ActorID != "42" {
			t.Errorf("actor not preserved: %+v", got[0])
		}
	})

	t.Run("audit log pagination", func(t *testing.T) {
		s := newStore(t)
		for i := 0; i < 5; i++ {
			_ = s.LogAudit(models.AuditEvent{
				ActorKind:  models.AuditActorAnon,
				Action:     models.AuditActionURLCreate,
				TargetKind: "url",
				TargetID:   "p" + string(rune('a'+i)),
			})
		}
		page1, _ := s.RecentAuditEvents(2, 0)
		page2, _ := s.RecentAuditEvents(2, 2)
		if len(page1) != 2 || len(page2) != 2 {
			t.Fatalf("page lengths: %d, %d, want 2/2", len(page1), len(page2))
		}
		// Pages must not overlap.
		if page1[0].ID == page2[0].ID || page1[1].ID == page2[1].ID {
			t.Errorf("pages overlap: %v vs %v", page1, page2)
		}
	})

	t.Run("click event preserves country", func(t *testing.T) {
		s := newStore(t)
		_ = s.Set("co", &models.URLMapping{
			ID: "co", OriginalURL: "https://example.com", CreatedAt: time.Now(),
		})
		if err := s.RecordClick("co", models.ClickEvent{
			At:      time.Now(),
			UAClass: "desktop",
			Country: "DE",
		}); err != nil {
			t.Fatalf("RecordClick: %v", err)
		}
		got, err := s.RecentClicks("co", 1)
		if err != nil {
			t.Fatalf("RecentClicks: %v", err)
		}
		if len(got) != 1 || got[0].Country != "DE" {
			t.Errorf("Country = %q, want DE (events=%+v)", got[0].Country, got)
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
