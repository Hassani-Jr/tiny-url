package services

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"tiny-url/models"
)

// TestSQLiteDeleteCascadesClickEvents asserts the foreign-key ON DELETE
// CASCADE actually fires. Without PRAGMA foreign_keys=on it would not — so
// this test guards against a future driver change or DSN edit silently
// breaking the click-event cleanup path.
func TestSQLiteDeleteCascadesClickEvents(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "cascade.db")
	store, err := NewSQLiteStore(tmp)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	const code = "cascade"
	if err := store.Set(code, &models.URLMapping{
		ID: code, OriginalURL: "https://example.com", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := store.RecordClick(code, models.ClickEvent{
			At: time.Now(), UAClass: "desktop",
		}); err != nil {
			t.Fatalf("RecordClick: %v", err)
		}
	}

	if err := store.Delete(code); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	var n int
	row := store.db.QueryRow(`SELECT COUNT(*) FROM click_events WHERE short_code = ?`, code)
	if err := row.Scan(&n); err != nil {
		t.Fatalf("count clicks: %v", err)
	}
	if n != 0 {
		t.Errorf("click_events rows after Delete = %d, want 0 (cascade did not fire)", n)
	}
}

func TestSQLiteStoreCRUD(t *testing.T) {
	// Create temporary database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	defer store.Close()

	t.Run("set and get", func(t *testing.T) {
		code := "test123"
		now := time.Now()
		mapping := &models.URLMapping{
			ID:          code,
			OriginalURL: "https://example.com",
			CreatedAt:   now,
			ClickCount:  0,
		}

		err := store.Set(code, mapping)
		if err != nil {
			t.Errorf("Set() error = %v", err)
		}

		retrieved, err := store.Get(code)
		if err != nil {
			t.Errorf("Get() error = %v", err)
		}

		if retrieved == nil {
			t.Fatal("Get() returned nil")
		}

		if retrieved.ID != code {
			t.Errorf("Get() ID = %q, want %q", retrieved.ID, code)
		}

		if retrieved.OriginalURL != "https://example.com" {
			t.Errorf("Get() OriginalURL = %q, want https://example.com", retrieved.OriginalURL)
		}
	})

	t.Run("get nonexistent returns error", func(t *testing.T) {
		_, err := store.Get("nonexistent")
		if err == nil {
			t.Error("Get() nonexistent should return error")
		}

		if err != ErrNotFound {
			t.Errorf("Get() error = %v, want ErrNotFound", err)
		}
	})

	t.Run("exists", func(t *testing.T) {
		code := "exists"
		mapping := &models.URLMapping{
			ID:          code,
			OriginalURL: "https://example.com",
			CreatedAt:   time.Now(),
		}

		store.Set(code, mapping)

		if !store.Exists(code) {
			t.Errorf("Exists() = false, want true for code %q", code)
		}

		if store.Exists("doesntexist") {
			t.Error("Exists() = true for nonexistent code, want false")
		}
	})

	t.Run("set with existing code returns ErrCodeConflict and preserves original", func(t *testing.T) {
		// Set is non-upsert by design: a re-Set on an existing code must
		// fail with ErrCodeConflict so the shorten handler can map it to
		// 409. Silently overwriting would let a TOCTOU racer clobber the
		// first writer's owner-token hash.
		code := "noupdate"
		mapping1 := &models.URLMapping{
			ID:          code,
			OriginalURL: "https://1.1.1.1/first",
			CreatedAt:   time.Now(),
		}

		if err := store.Set(code, mapping1); err != nil {
			t.Fatalf("First Set() error = %v", err)
		}

		mapping2 := &models.URLMapping{
			ID:          code,
			OriginalURL: "https://1.1.1.1/second",
			CreatedAt:   time.Now(),
		}

		err := store.Set(code, mapping2)
		if !errors.Is(err, ErrCodeConflict) {
			t.Errorf("Second Set() error = %v, want ErrCodeConflict", err)
		}

		retrieved, _ := store.Get(code)
		if retrieved.OriginalURL != "https://1.1.1.1/first" {
			t.Errorf("Get() OriginalURL = %q, want first mapping preserved", retrieved.OriginalURL)
		}
	})
}

func TestSQLiteStoreExpiration(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_expiration.db")

	store, _ := NewSQLiteStore(dbPath)
	defer store.Close()

	code := "expiring"
	now := time.Now()
	expiredTime := now.Add(-1 * time.Hour) // Already expired
	mapping := &models.URLMapping{
		ID:          code,
		OriginalURL: "https://example.com",
		CreatedAt:   now,
		ExpiresAt:   &expiredTime,
	}

	store.Set(code, mapping)

	// Should return ErrExpired
	_, err := store.Get(code)
	if err != ErrExpired {
		t.Errorf("Get() error = %v, want ErrExpired", err)
	}
}

func TestSQLiteStoreClicks(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_clicks.db")

	store, _ := NewSQLiteStore(dbPath)
	defer store.Close()

	code := "clicks"
	mapping := &models.URLMapping{
		ID:          code,
		OriginalURL: "https://example.com",
		CreatedAt:   time.Now(),
		ClickCount:  0,
	}

	store.Set(code, mapping)

	// Record clicks via the unified atomic method.
	now := time.Now()
	if err := store.RecordClick(code, models.ClickEvent{At: now}); err != nil {
		t.Fatalf("RecordClick: %v", err)
	}

	retrieved, _ := store.Get(code)
	if retrieved.ClickCount != 1 {
		t.Errorf("After 1 increment: ClickCount = %d, want 1", retrieved.ClickCount)
	}

	// Record again
	if err := store.RecordClick(code, models.ClickEvent{At: now.Add(10 * time.Second)}); err != nil {
		t.Fatalf("RecordClick: %v", err)
	}

	retrieved, _ = store.Get(code)
	if retrieved.ClickCount != 2 {
		t.Errorf("After 2 increments: ClickCount = %d, want 2", retrieved.ClickCount)
	}

	// Check LastAccessed was updated
	if retrieved.LastAccessed == nil {
		t.Error("LastAccessed should not be nil")
	}
}

func TestSQLiteStoreCleanup(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_cleanup.db")

	store, _ := NewSQLiteStore(dbPath)
	defer store.Close()

	now := time.Now()

	// Add expired URL
	expiredTime := now.Add(-1 * time.Hour)
	store.Set("expired1", &models.URLMapping{
		ID:          "expired1",
		OriginalURL: "https://example.com",
		CreatedAt:   now,
		ExpiresAt:   &expiredTime,
	})

	// Add non-expired URL
	store.Set("active", &models.URLMapping{
		ID:          "active",
		OriginalURL: "https://example.com",
		CreatedAt:   now,
	})

	// Add another expired URL
	futureExpire := now.Add(-10 * time.Minute)
	store.Set("expired2", &models.URLMapping{
		ID:          "expired2",
		OriginalURL: "https://example.com",
		CreatedAt:   now,
		ExpiresAt:   &futureExpire,
	})

	// Start cleanup routine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store.StartCleanupRoutine(ctx, 50*time.Millisecond)

	// Wait for cleanup to run
	time.Sleep(200 * time.Millisecond)

	// Expired URLs should be gone
	if store.Exists("expired1") {
		t.Error("Cleanup failed: expired1 still exists")
	}

	if store.Exists("expired2") {
		t.Error("Cleanup failed: expired2 still exists")
	}

	// Active URL should still exist
	if !store.Exists("active") {
		t.Error("Cleanup removed non-expired URL")
	}
}

func TestSQLiteStorePersistence(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_persist.db")

	// Create store and add data
	{
		store, _ := NewSQLiteStore(dbPath)

		mapping := &models.URLMapping{
			ID:          "persist",
			OriginalURL: "https://example.com",
			CreatedAt:   time.Now(),
			ClickCount:  42,
		}

		store.Set("persist", mapping)
		store.Close()
	}

	// Re-open store and verify data is still there
	{
		store, _ := NewSQLiteStore(dbPath)
		defer store.Close()

		retrieved, err := store.Get("persist")
		if err != nil {
			t.Errorf("Get() after reopening: error = %v", err)
		}

		if retrieved.OriginalURL != "https://example.com" {
			t.Errorf("OriginalURL = %q, want https://example.com", retrieved.OriginalURL)
		}

		if retrieved.ClickCount != 42 {
			t.Errorf("ClickCount = %d, want 42", retrieved.ClickCount)
		}
	}
}

func TestSQLiteStoreClose(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_close.db")

	store, _ := NewSQLiteStore(dbPath)

	// Add data
	store.Set("test", &models.URLMapping{
		ID:          "test",
		OriginalURL: "https://example.com",
		CreatedAt:   time.Now(),
	})

	// Close should succeed
	err := store.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Operations after close should fail gracefully
	_, err = store.Get("test")
	if err == nil {
		t.Error("Get() after Close() should error")
	}
}

func TestSQLiteStoreTokenHash(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_token.db")

	store, _ := NewSQLiteStore(dbPath)
	defer store.Close()

	code := "withtoken"
	tokenHash := []byte("somehash")

	mapping := &models.URLMapping{
		ID:             code,
		OriginalURL:    "https://example.com",
		CreatedAt:      time.Now(),
		OwnerTokenHash: tokenHash,
	}

	store.Set(code, mapping)

	retrieved, _ := store.Get(code)
	if !bytesEqual(retrieved.OwnerTokenHash, tokenHash) {
		t.Errorf("OwnerTokenHash mismatch: got %v, want %v", retrieved.OwnerTokenHash, tokenHash)
	}
}

// Helper function to compare byte slices
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
