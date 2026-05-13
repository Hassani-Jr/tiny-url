package main

import (
	"context"
	"net/http"
	"time"

	"log/slog"

	"tiny-url/config"
	"tiny-url/handlers"
	"tiny-url/middleware"
	"tiny-url/services"
)

// buildHandler wires every handler, mux, and middleware into a single root
// http.Handler. Extracted from main() so the end-to-end test can drive the
// real chain via httptest.NewServer without spinning up a real listener
// or shelling out to `go run .`.
//
// The caller supplies an already-opened store so tests can inject a
// MemoryStore without needing the env-var-driven openStore() path. Limiter
// goroutines bind to the supplied ctx — pass a cancellable one in tests so
// they exit cleanly on cleanup.
func buildHandler(ctx context.Context, cfg config.Config, store services.Store) (http.Handler, error) {
	denyList, err := loadDenyList(cfg)
	if err != nil {
		return nil, err
	}
	if denyList != nil {
		slog.Info("deny-list active", "hosts", denyList.Size())
	}

	// IP-hash salt is initialised even when LogClickIP is off — installing a
	// salt is cheap, and tests / future env updates that flip the flag don't
	// need to re-bootstrap.
	services.SetClickSalt(cfg.ClickIPSalt)

	clickStream := services.NewClickStream()
	dnsCache := services.NewDNSCache(5*time.Second, 1024)
	geoIP := services.NewGeoIP()
	webhookDispatcher := services.NewWebhookDispatcher(
		cfg.WebhookWorkers, cfg.WebhookQueueSize, cfg.WebhookTimeout,
	)
	// Tied to the request-handling lifecycle: stop accepting deliveries
	// and drain the queue once the parent context (SIGTERM) fires.
	go func() {
		<-ctx.Done()
		webhookDispatcher.Close()
	}()

	staticAssets, err := handlers.NewStaticAssets(staticDirFS())
	if err != nil {
		return nil, err
	}

	shortenHandler := handlers.NewShortenHandler(store, cfg.BaseURL, cfg.MaxExpirationMinutes, cfg.MaxBodyBytes, denyList)
	redirectHandler := handlers.NewRedirectHandler(store, handlers.RedirectConfig{
		DenyList:   denyList,
		TrustProxy: cfg.TrustProxy,
		LogIP:      cfg.LogClickIP,
		Stream:     clickStream,
		DNSCache:   dnsCache,
		Webhook:    webhookDispatcher,
		GeoIP:      geoIP,
	})
	streamHandler := handlers.NewStreamHandler(store, clickStream)
	analyticsHandler := handlers.NewAnalyticsHandler(store)
	clicksHandler := handlers.NewClicksHandler(store, 200)
	seriesHandler := handlers.NewSeriesHandler(store)
	deleteHandler := handlers.NewDeleteHandler(store)
	patchHandler := handlers.NewPatchHandler(store, cfg.MaxExpirationMinutes, cfg.MaxBodyBytes, denyList)
	rotateHandler := handlers.NewRotateHandler(store)
	badgeHandler := handlers.NewBadgeHandler(store)
	qrHandler := handlers.NewQRHandler(store, cfg.BaseURL)
	healthHandler := handlers.NewHealthHandler(storageBackendName(cfg.StorageBackend))
	readyHandler := handlers.NewReadyHandler(store, 2*time.Second)
	apiKeyHandler := handlers.NewAPIKeyHandler(store)
	myURLsHandler := handlers.NewMyURLsHandler(store, 100)

	writeLimiter := middleware.NewLimiter(ctx, cfg.WriteRatePerMin, time.Minute, cfg.TrustProxy)
	readLimiter := middleware.NewLimiter(ctx, cfg.ReadRatePerMin, time.Minute, cfg.TrustProxy)

	// appMux: rate-limited application routes. PATCH and DELETE are both
	// gated by the per-URL admin token, which a cross-origin page cannot
	// read out of localStorage on this origin — the bearer token is the
	// real CSRF defence. The X-Requested-With check stays on POST /api/shorten
	// (which has no auth) and is intentionally NOT applied to PATCH/DELETE
	// for consistency.
	appMux := http.NewServeMux()
	appMux.Handle("POST /api/shorten",
		writeLimiter.Middleware(middleware.RequireXRequestedWith(shortenHandler)))
	appMux.Handle("DELETE /api/url/{code}",
		writeLimiter.Middleware(deleteHandler))
	appMux.Handle("PATCH /api/url/{code}",
		writeLimiter.Middleware(patchHandler))
	appMux.Handle("POST /api/url/{code}/rotate",
		writeLimiter.Middleware(rotateHandler))
	// /api/keys: POST creates (mints a fresh API key), the others
	// require a valid bearer that resolves to a stored key. POST is on
	// the write limiter + XHR header (matches /api/shorten); read paths
	// fall through the read limiter only.
	appMux.Handle("POST /api/keys",
		writeLimiter.Middleware(middleware.RequireXRequestedWith(apiKeyHandler)))
	appMux.Handle("GET /api/keys", apiKeyHandler)
	appMux.Handle("PATCH /api/keys", apiKeyHandler)
	appMux.Handle("DELETE /api/keys", apiKeyHandler)
	appMux.Handle("GET /api/urls", myURLsHandler)
	appMux.Handle("GET /api/analytics/{code}", analyticsHandler)
	appMux.Handle("GET /api/analytics/{code}/clicks", clicksHandler)
	appMux.Handle("GET /api/analytics/{code}/series", seriesHandler)
	// Live event stream (SSE). Mounted on appMux so it goes through the
	// read rate limiter, but a single connection counts once and stays
	// open — repeat traffic is the click events themselves, not new
	// requests, so the limiter doesn't really apply here in practice.
	appMux.Handle("GET /api/analytics/{code}/stream", streamHandler)
	appMux.Handle("GET /api/qr/{code}", qrHandler)
	// Badges are aggressively cached and embedded into third-party pages.
	// Mount under appMux so the read rate-limit applies (an embed on a
	// hot page could spam the endpoint), but the 60-second Cache-Control
	// keeps the limiter from being a real obstacle.
	appMux.Handle("GET /api/badge/{code}", badgeHandler)
	appMux.Handle("GET /{code}", redirectHandler)
	// POST /{code} is the submission path for the password interstitial.
	// Going through the same handler keeps the password verification next
	// to the redirect logic and lets the form post to its own URL. Not
	// subject to RequireXRequestedWith — the form is rendered server-side
	// from a cross-origin click, and the body is a passphrase that an
	// attacker would need to know to make this request useful anyway.
	appMux.Handle("POST /{code}", redirectHandler)
	appMux.Handle("GET /static/", staticAssets.FileServer())
	appMux.HandleFunc("GET /", staticAssets.ServeIndex)

	// outerMux: probes are mounted OUTSIDE the read rate-limiter so a busy
	// Kubernetes liveness/readiness loop can't deplete the bucket and start
	// 429-ing real traffic. /favicon.ico likewise stops falling through to
	// the redirect handler and counting toward the budget.
	outerMux := http.NewServeMux()
	outerMux.Handle("GET /healthz", healthHandler)
	outerMux.Handle("GET /readyz", readyHandler)
	outerMux.Handle("GET /metrics", middleware.GatedMetricsHandler(cfg.MetricsToken))
	if cfg.MetricsToken != "" {
		slog.Info("metrics endpoint requires bearer token (METRICS_TOKEN set)")
	}
	outerMux.Handle("GET /favicon.ico", handlers.FaviconHandler())
	outerMux.Handle("/", readLimiter.Middleware(appMux))

	// Middleware order (outermost → innermost):
	//   RequestID → Logger → Metrics → Recover → SecurityHeaders → outerMux
	//
	// RequestID first so every log/metric carries the ID. Logger and Metrics
	// wrap Recover so their wrapped responseWriters observe the 500 status
	// the recover branch sets — without that, a panicked handler would be
	// counted as 2xx and logged with status=200. SecurityHeaders sits inside
	// Recover so the standard headers still ship on the recovered 500.
	return middleware.RequestID(
		middleware.Logger(
			middleware.Metrics(
				middleware.Recover(
					middleware.SecurityHeaders(cfg.TLSEnabled())(outerMux),
				),
			),
		),
	), nil
}
