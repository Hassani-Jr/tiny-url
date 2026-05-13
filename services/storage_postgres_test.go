package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"
	"tiny-url/models"
)

// postgresDSN returns the connection string for the test database, or
// "" when the env var is unset. Tests gated on this skip cleanly so CI
// without a Postgres container (the default) doesn't fail; running
// locally is just `TEST_POSTGRES_DSN=postgres://... go test ./services`.
//
// The DSN is expected to point at an empty database — every test starts
// by truncating the four tables to give itself a clean slate. We
// deliberately don't dump-and-recreate the schema; the production
// migration path is what we want to exercise.
func postgresDSN() string {
	return os.Getenv("TEST_POSTGRES_DSN")
}

// newPostgresStoreForTest opens a connection, applies the schema, and
// truncates every table so the test sees an empty database. Returns
// nil + a Skip when the env var is unset.
func newPostgresStoreForTest(t *testing.T) *PostgresStore {
	t.Helper()
	dsn := postgresDSN()
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set — skipping Postgres backend test")
	}
	s, err := NewPostgresStore(dsn)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	// Truncating click_events isn't strictly required because of the
	// FK CASCADE on urls, but doing it explicitly keeps the test
	// deterministic if a future migration weakens that relationship.
	for _, tbl := range []string{"click_events", "urls", "api_keys"} {
		if _, err := s.db.Exec("TRUNCATE TABLE " + tbl + " RESTART IDENTITY CASCADE"); err != nil {
			t.Fatalf("truncate %s: %v", tbl, err)
		}
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestPostgresStoreContract runs the cross-backend contract suite
// against a real Postgres connection. Skips when the test DSN is
// absent — CI without Postgres just sees a PASS-SKIP, while local
// runs with TEST_POSTGRES_DSN exercise every Store method.
func TestPostgresStoreContract(t *testing.T) {
	if postgresDSN() == "" {
		t.Skip("TEST_POSTGRES_DSN not set")
	}
	runStoreContractTests(t, func(t *testing.T) Store {
		return newPostgresStoreForTest(t)
	})
}

// TestPostgresStoreSetConflict is Postgres-specific — verifies that
// the ON CONFLICT DO NOTHING / RowsAffected==0 path correctly maps to
// ErrCodeConflict, matching the SQLite contract.
func TestPostgresStoreSetConflict(t *testing.T) {
	s := newPostgresStoreForTest(t)
	m := &models.URLMapping{
		ID: "dup", OriginalURL: "https://x.example", CreatedAt: time.Now(),
	}
	if err := s.Set("dup", m); err != nil {
		t.Fatalf("first Set: %v", err)
	}
	err := s.Set("dup", m)
	if err != ErrCodeConflict {
		t.Errorf("second Set: %v, want ErrCodeConflict", err)
	}
}

// TestPostgresStorePingTimeout exercises the readyz happy path — a
// healthy DB pings within the cap.
func TestPostgresStorePingTimeout(t *testing.T) {
	s := newPostgresStoreForTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Ping(ctx); err != nil {
		t.Errorf("Ping = %v, want nil", err)
	}
}

// TestPostgresStoreUniqueTokenHashCollision documents an edge case in
// the api_keys.token_hash UNIQUE constraint: a duplicate (vanishingly
// rare with 32 random bytes) surfaces as a driver-level UNIQUE
// violation, not ErrCodeConflict. CreateAPIKey doesn't translate it
// because the application can't recover here anyway — log the error
// and let the caller decide.
func TestPostgresStoreDuplicateTokenHash(t *testing.T) {
	s := newPostgresStoreForTest(t)
	hash := randHashForTest(t)
	if _, err := s.CreateAPIKey("first", hash); err != nil {
		t.Fatalf("first CreateAPIKey: %v", err)
	}
	if _, err := s.CreateAPIKey("second", hash); err == nil {
		t.Errorf("second CreateAPIKey with duplicate hash succeeded, want error")
	}
}

func randHashForTest(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	// hex-decode-and-re-encode is overkill; this is just here to make
	// the test fixture deterministic if we ever want to print it.
	_ = hex.EncodeToString(b)
	return b
}

// Compile-time check that PostgresStore implements Store. Catches
// signature drift if the interface evolves without the backend
// keeping up.
var _ Store = (*PostgresStore)(nil)

// avoid unused-import lint when the suite skips on most machines.
var _ = fmt.Sprintf
