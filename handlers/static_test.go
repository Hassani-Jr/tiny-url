package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

// fakeStatic is a tiny in-memory FS so tests don't depend on the embed
// living in package main. Keeps these unit tests pure.
func fakeStatic(t *testing.T) *StaticAssets {
	t.Helper()
	fs := fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<!doctype html>hi")},
		"app.js":     &fstest.MapFile{Data: []byte("console.log('test');")},
	}
	a, err := NewStaticAssets(fs)
	if err != nil {
		t.Fatalf("NewStaticAssets: %v", err)
	}
	return a
}

func TestServeIndexFromEmbed(t *testing.T) {
	a := fakeStatic(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	a.ServeIndex(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if got := w.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/html; charset=utf-8", got)
	}
	if w.Body.String() != "<!doctype html>hi" {
		t.Errorf("body = %q, want exact embedded content", w.Body.String())
	}
}

func TestServeIndexNonRoot404(t *testing.T) {
	a := fakeStatic(t)
	req := httptest.NewRequest(http.MethodGet, "/something-else", nil)
	w := httptest.NewRecorder()
	a.ServeIndex(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestStaticFileServerServesEmbedded(t *testing.T) {
	a := fakeStatic(t)
	mux := http.NewServeMux()
	mux.Handle("GET /static/", a.FileServer())
	req := httptest.NewRequest(http.MethodGet, "/static/app.js", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if w.Body.String() != "console.log('test');" {
		t.Errorf("body = %q, want embedded JS", w.Body.String())
	}
}

func TestFaviconHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
	w := httptest.NewRecorder()
	FaviconHandler().ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", w.Code)
	}
	if w.Header().Get("Cache-Control") == "" {
		t.Errorf("favicon should set Cache-Control to keep browsers from re-fetching")
	}
}
