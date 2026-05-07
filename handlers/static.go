package handlers

import (
	"io/fs"
	"net/http"
)

// StaticAssets bundles the handlers that need access to the embedded
// static/ directory. The embed.FS lives in package main (because go:embed
// resolves paths relative to the file containing the directive, and only
// main has ./static next to it). main wires this up at startup.
type StaticAssets struct {
	indexHTML []byte
	staticFS  http.Handler
}

// NewStaticAssets prepares the index page and the /static/ file server from
// the supplied embedded FS. Pass the result of fs.Sub(embedded, "static") so
// the index lookup and the file server agree on the root.
//
// indexHTML is read once and cached so each page load doesn't re-walk the
// embedded FS. The cost is one allocation at startup.
func NewStaticAssets(staticDir fs.FS) (*StaticAssets, error) {
	idx, err := fs.ReadFile(staticDir, "index.html")
	if err != nil {
		return nil, err
	}
	return &StaticAssets{
		indexHTML: idx,
		staticFS:  http.StripPrefix("/static/", http.FileServer(http.FS(staticDir))),
	}, nil
}

// ServeIndex emits the cached index.html.
func (a *StaticAssets) ServeIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(a.indexHTML)
}

// FileServer returns the handler for /static/* requests.
func (a *StaticAssets) FileServer() http.Handler { return a.staticFS }

// FaviconHandler returns 204 for /favicon.ico. Browsers auto-fetch this on
// every page load; without an explicit handler it falls through to
// GET /{code}, returns 404, eats redirect rate-limit budget, and pollutes
// logs. 204 is preferable to serving an actual icon because we don't have
// one and the response body would be empty either way.
func FaviconHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.WriteHeader(http.StatusNoContent)
	})
}
