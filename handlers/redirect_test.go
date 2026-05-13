package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tiny-url/models"
	"tiny-url/services"
)

func TestRedirectHandler(t *testing.T) {
	t.Run("valid redirect", func(t *testing.T) {
		store := services.NewMemoryStore()
		handler := NewRedirectHandler(store, RedirectConfig{})
		mux := http.NewServeMux()
		mux.Handle("GET /{code}", handler)

		now := time.Now()
		store.Set("valid", &models.URLMapping{
			ID:          "valid",
			OriginalURL: "https://1.1.1.1",
			CreatedAt:   now,
		})

		req := httptest.NewRequest("GET", "/valid", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("status = %d, want 302", w.Code)
		}

		location := w.Header().Get("Location")
		if location != "https://1.1.1.1" {
			t.Errorf("Location = %q, want https://example.com", location)
		}
	})

	t.Run("code not found", func(t *testing.T) {
		store := services.NewMemoryStore()
		handler := NewRedirectHandler(store, RedirectConfig{})
		mux := http.NewServeMux()
		mux.Handle("GET /{code}", handler)

		req := httptest.NewRequest("GET", "/notfound", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", w.Code)
		}
	})

	t.Run("expired url", func(t *testing.T) {
		store := services.NewMemoryStore()
		handler := NewRedirectHandler(store, RedirectConfig{})
		mux := http.NewServeMux()
		mux.Handle("GET /{code}", handler)

		now := time.Now()
		expiredTime := now.Add(-1 * time.Hour)
		store.Set("expired", &models.URLMapping{
			ID:          "expired",
			OriginalURL: "https://1.1.1.1",
			CreatedAt:   now,
			ExpiresAt:   &expiredTime,
		})

		req := httptest.NewRequest("GET", "/expired", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusGone {
			t.Errorf("status = %d, want 410", w.Code)
		}
	})

	t.Run("redirect with query string", func(t *testing.T) {
		store := services.NewMemoryStore()
		handler := NewRedirectHandler(store, RedirectConfig{})
		mux := http.NewServeMux()
		mux.Handle("GET /{code}", handler)

		now := time.Now()
		store.Set("query", &models.URLMapping{
			ID:          "query",
			OriginalURL: "https://1.1.1.1/page?foo=bar",
			CreatedAt:   now,
		})

		req := httptest.NewRequest("GET", "/query", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		location := w.Header().Get("Location")
		if location != "https://1.1.1.1/page?foo=bar" {
			t.Errorf("Location = %q, want https://example.com/page?foo=bar", location)
		}
	})

	t.Run("redirect with fragment", func(t *testing.T) {
		store := services.NewMemoryStore()
		handler := NewRedirectHandler(store, RedirectConfig{})
		mux := http.NewServeMux()
		mux.Handle("GET /{code}", handler)

		now := time.Now()
		store.Set("fragment", &models.URLMapping{
			ID:          "fragment",
			OriginalURL: "https://1.1.1.1#section",
			CreatedAt:   now,
		})

		req := httptest.NewRequest("GET", "/fragment", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		location := w.Header().Get("Location")
		if location != "https://1.1.1.1#section" {
			t.Errorf("Location = %q, want https://example.com#section", location)
		}
	})
}

func TestRedirectHandlerClickTracking(t *testing.T) {
	store := services.NewMemoryStore()
	handler := NewRedirectHandler(store, RedirectConfig{})
	mux := http.NewServeMux()
	mux.Handle("GET /{code}", handler)

	code := "track"
	now := time.Now()
	store.Set(code, &models.URLMapping{
		ID:          code,
		OriginalURL: "https://1.1.1.1",
		CreatedAt:   now,
		ClickCount:  0,
	})

	// First redirect
	req := httptest.NewRequest("GET", "/"+code, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	// Get updated mapping and check click count
	mapping, err := store.Get(code)
	if err != nil {
		t.Fatalf("store.Get() error = %v", err)
	}

	if mapping.ClickCount != 1 {
		t.Errorf("After 1 click: ClickCount = %d, want 1", mapping.ClickCount)
	}

	// Second redirect
	req2 := httptest.NewRequest("GET", "/"+code, nil)
	w2 := httptest.NewRecorder()
	mux.ServeHTTP(w2, req2)

	// Check click count again
	mapping2, _ := store.Get(code)
	if mapping2.ClickCount != 2 {
		t.Errorf("After 2 clicks: ClickCount = %d, want 2", mapping2.ClickCount)
	}
}

func TestRedirectHandlerLastAccessed(t *testing.T) {
	store := services.NewMemoryStore()
	handler := NewRedirectHandler(store, RedirectConfig{})
	mux := http.NewServeMux()
	mux.Handle("GET /{code}", handler)

	code := "lastaccess"
	now := time.Now()
	store.Set(code, &models.URLMapping{
		ID:          code,
		OriginalURL: "https://1.1.1.1",
		CreatedAt:   now,
	})

	req := httptest.NewRequest("GET", "/"+code, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	// Get mapping and check last_accessed was updated
	mapping, _ := store.Get(code)
	if mapping.LastAccessed == nil {
		t.Error("LastAccessed should not be nil after redirect")
	}

	// Last accessed should be very recent (within 1 second)
	if mapping.LastAccessed != nil && time.Since(*mapping.LastAccessed) > time.Second {
		t.Errorf("LastAccessed is too old: %v", time.Since(*mapping.LastAccessed))
	}
}

func TestRedirectHandlerEmptyCode(t *testing.T) {
	store := services.NewMemoryStore()
	handler := NewRedirectHandler(store, RedirectConfig{})
	mux := http.NewServeMux()
	mux.Handle("GET /{code}", handler)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestRedirectHandlerDeniedAfterCreation(t *testing.T) {
	// A short URL is created BEFORE the operator adds the destination host
	// to the deny-list. The redirect handler must re-check at request time
	// and return 451 — otherwise stale short URLs keep resolving to a
	// now-banned host until the cleanup catches them.
	store := services.NewMemoryStore()
	deny := services.NewDenyList([]string{"laterbad.example"})
	handler := NewRedirectHandler(store, RedirectConfig{DenyList: deny})
	mux := http.NewServeMux()
	mux.Handle("GET /{code}", handler)

	now := time.Now()
	store.Set("stale", &models.URLMapping{
		ID:          "stale",
		OriginalURL: "https://www.laterbad.example/path",
		CreatedAt:   now,
	})

	req := httptest.NewRequest("GET", "/stale", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnavailableForLegalReasons {
		t.Errorf("status = %d, want 451 for redirect-time deny match", w.Code)
	}
	// Click count must not increment for blocked redirects.
	if mapping, _ := store.Get("stale"); mapping.ClickCount != 0 {
		t.Errorf("ClickCount = %d, want 0 for blocked redirect", mapping.ClickCount)
	}
}

func TestRedirectHandlerBlocksReboundIP(t *testing.T) {
	// Simulates the DNS-rebinding outcome: a stored URL whose host now
	// resolves (or always was) a private/loopback IP. The redirect handler
	// must catch this at click time even though creation-time validation
	// would have rejected it. We bypass creation-time validation by Set'ing
	// a private-IP URL directly, mirroring what a successful rebind would
	// look like to the redirect handler.
	store := services.NewMemoryStore()
	handler := NewRedirectHandler(store, RedirectConfig{})
	mux := http.NewServeMux()
	mux.Handle("GET /{code}", handler)

	store.Set("rebind", &models.URLMapping{
		ID:          "rebind",
		OriginalURL: "http://127.0.0.1/admin", // would-have-rebound destination
		CreatedAt:   time.Now(),
	})

	req := httptest.NewRequest("GET", "/rebind", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnavailableForLegalReasons {
		t.Errorf("status = %d, want 451 — rebound host must not redirect", w.Code)
	}
	// Click count must NOT increment when the destination is blocked at runtime.
	if mapping, _ := store.Get("rebind"); mapping.ClickCount != 0 {
		t.Errorf("ClickCount = %d, want 0 for blocked rebind redirect", mapping.ClickCount)
	}
}

func TestRedirectHandlerCustomCode(t *testing.T) {
	// IP literal so the redirect handler's runtime SSRF re-check (which
	// catches DNS rebinding) doesn't get derailed by a /etc/hosts entry
	// pointing example.com at 127.0.0.1 — a common dev-laptop trap.
	store := services.NewMemoryStore()
	handler := NewRedirectHandler(store, RedirectConfig{})
	mux := http.NewServeMux()
	mux.Handle("GET /{code}", handler)

	code := "my-custom-link"
	now := time.Now()
	store.Set(code, &models.URLMapping{
		ID:          code,
		OriginalURL: "https://1.1.1.1/long/path",
		CreatedAt:   now,
	})

	req := httptest.NewRequest("GET", "/"+code, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", w.Code)
	}

	location := w.Header().Get("Location")
	if location != "https://1.1.1.1/long/path" {
		t.Errorf("Location = %q, want https://1.1.1.1/long/path", location)
	}
}

func TestRedirectClickCap(t *testing.T) {
	// A URL with MaxClicks=2 should redirect twice, then return 410 Gone
	// without serving the destination URL or recording a click event.
	store := services.NewMemoryStore()
	handler := NewRedirectHandler(store, RedirectConfig{})
	mux := http.NewServeMux()
	mux.Handle("GET /{code}", handler)

	store.Set("cap", &models.URLMapping{
		ID:          "cap",
		OriginalURL: "https://1.1.1.1/",
		CreatedAt:   time.Now(),
		MaxClicks:   2,
	})

	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", "/cap", nil))
		if w.Code != http.StatusFound {
			t.Fatalf("attempt %d: status = %d, want 302", i+1, w.Code)
		}
	}
	// Third hit must be Gone.
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/cap", nil))
	if w.Code != http.StatusGone {
		t.Errorf("post-cap status = %d, want 410", w.Code)
	}
	if !strings.Contains(w.Body.String(), "click limit") {
		t.Errorf("body should mention click limit, got %q", w.Body.String())
	}
}

func TestRedirectPasswordGate(t *testing.T) {
	// A password-protected URL must:
	//   - serve an HTML interstitial on GET (no Location header)
	//   - reject wrong password POST with 401 + form
	//   - redirect on correct password POST
	store := services.NewMemoryStore()
	handler := NewRedirectHandler(store, RedirectConfig{})
	mux := http.NewServeMux()
	mux.Handle("GET /{code}", handler)
	mux.Handle("POST /{code}", handler)

	hash, salt, err := hashPassword("hunter2")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	store.Set("pw", &models.URLMapping{
		ID:           "pw",
		OriginalURL:  "https://1.1.1.1/secret",
		CreatedAt:    time.Now(),
		PasswordHash: hash,
		PasswordSalt: salt,
	})

	// GET → interstitial form, no redirect
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/pw", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200 (form)", w.Code)
	}
	if w.Header().Get("Location") != "" {
		t.Errorf("GET set Location header on password form — destination leaked")
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("form Content-Type = %q, want text/html", ct)
	}
	if !strings.Contains(w.Body.String(), "password") {
		t.Errorf("form body missing password field")
	}

	// Wrong password → 401, still form
	wrongBody := strings.NewReader("password=wrong")
	req := httptest.NewRequest("POST", "/pw", wrongBody)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("wrong password status = %d, want 401", w.Code)
	}
	if w.Header().Get("Location") != "" {
		t.Errorf("wrong-password response leaked Location header")
	}

	// Right password → 302 + redirect to destination
	rightBody := strings.NewReader("password=hunter2")
	req = httptest.NewRequest("POST", "/pw", rightBody)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Errorf("correct password status = %d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "https://1.1.1.1/secret" {
		t.Errorf("Location = %q, want destination after correct password", loc)
	}

	// Correct password counted as a click (only one — the failed POST and
	// the GET interstitial must NOT have incremented).
	m, _ := store.Get("pw")
	if m.ClickCount != 1 {
		t.Errorf("ClickCount after one successful redirect = %d, want 1 (interstitial GET and wrong-password POST must not count)", m.ClickCount)
	}
}
